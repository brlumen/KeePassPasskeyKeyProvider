using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// KeePass Key Provider using FIDO2 authentication via the Windows WebAuthn API
	/// with PRF extension support (WebAuthn Level 3).
	/// Database key K is 32 random bytes; the KDBX header (PublicCustomData) stores K ⊕ PRF_i
	/// for each device (see <see cref="DeviceKeyStore"/>). Credentials are discoverable: no files next to the database.
	/// Removing a device = rotation of K: the new K is re-wrapped for the remaining devices and the recovery phrase.
	/// </summary>
	public class FIDO2KeyProvider : KeyProvider
	{
		public const string ProviderName = "Passkey Key Provider (Windows WebAuthn)";

		/// <summary>
		/// Device created by the last GetKey(CreatingNewKey) call: credential ID, wrapped key K ⊕ PRF,
		/// label and SHA‑256 of K. The database is not yet available at this point; the record is written by
		/// <see cref="RegisterPendingDevice"/> when database settings are shown or on FileCreated / MasterKeyChanged events.
		/// </summary>
		private static byte[] pendingCredentialId;
		private static byte[] pendingWrappedKey;
		private static byte[] pendingKeyHash;
		private static string pendingLabel;

		/// <summary>
		/// Master key change keeping the other devices: the previous database key, used to re-wrap
		/// their wrapped keys for the new K (as in rotation). null — the other devices are removed.
		/// </summary>
		private static byte[] pendingOldKey;

		private readonly IPluginHost host;

		public FIDO2KeyProvider(IPluginHost host)
		{
			this.host = host;
		}

		private const string WebAuthnUnavailableMessage =
			"Windows WebAuthn API is not available.\n\n" +
			"This plugin requires Windows 10 22H2 or Windows 11 (WebAuthn API v4+).\n" +
			"Make sure your system meets the minimum requirements.";

		public override byte[] GetKey(KeyProviderQueryContext ctx)
		{
			try
			{
				if (!ctx.CreatingNewKey)
					return Unlock(ctx);

				if (!WebAuthnHelper.IsWebAuthnAvailable())
				{
					MessageService.ShowWarning(WebAuthnUnavailableMessage);
					return null;
				}
				return CreateNewCredential(ctx);
			}
			catch (WebAuthnException ex)
			{
				MessageService.ShowWarning($"FIDO2 authentication error:\n{ex.Message}");
				return null;
			}
			catch (Exception ex)
			{
				MessageService.ShowWarning($"Unexpected error:\n{ex.Message}\n\nType: {ex.GetType().Name}");
				return null;
			}
		}

		/// <summary>
		/// Creates a new credential and a random database key K; the wrapped key K ⊕ PRF awaits writing to the database.
		/// When changing the master key of an open database, the user chooses whether to keep its other devices.
		/// </summary>
		private byte[] CreateNewCredential(KeyProviderQueryContext ctx)
		{
			PwDatabase current = FindOpenDatabase(ctx);
			byte[] oldKey = GetDatabaseKey(current);
			List<DeviceRecord> existing = oldKey != null ? LoadRecordsSafe(current) : new List<DeviceRecord>();

			try
			{
				var form = new DeviceNameForm(existing.ConvertAll(r => r.Label));
				if (UIUtil.ShowDialogAndDestroy(form) != DialogResult.OK)
					return null;
				string label = form.DeviceName;
				bool keep = form.KeepDevices && existing.Count > 0;

				PrfResult created = CreateCredentialForDatabase(GetActiveWindowHandle(), ctx.DatabasePath);
				try
				{
					byte[] key = GenerateKey();
					pendingCredentialId = created.CredentialId;
					pendingWrappedKey = DeviceKeyStore.Wrap(key, created.PrfSecret);
					pendingKeyHash = HashKey(key);
					pendingLabel = label.Length > 0 ? label : DefaultLabel(created.Transport);
					pendingOldKey = keep ? (byte[])oldKey.Clone() : null;
					return key;
				}
				finally
				{
					MemUtil.ZeroByteArray(created.PrfSecret);
				}
			}
			finally
			{
				if (oldKey != null) MemUtil.ZeroByteArray(oldKey);
			}
		}

		/// <summary>Open database whose master key is being changed; null for a new database</summary>
		private PwDatabase FindOpenDatabase(KeyProviderQueryContext ctx)
		{
			string path = ctx.DatabaseIOInfo?.Path;
			if (host == null || string.IsNullOrEmpty(path)) return null;

			foreach (PwDocument doc in host.MainWindow.DocumentManager.Documents)
			{
				PwDatabase db = doc.Database;
				if (db != null && db.IsOpen && string.Equals(db.IOConnectionInfo.Path, path, StringComparison.OrdinalIgnoreCase))
					return db;
			}
			return null;
		}

		private static List<DeviceRecord> LoadRecordsSafe(PwDatabase db)
		{
			try { return DeviceKeyStore.Load(db); }
			catch { return new List<DeviceRecord>(); } // corrupted records cannot be kept anyway
		}

		/// <summary>
		/// Changes the database master key to the key of the last created credential, keeping the other devices
		/// </summary>
		public static bool PendingKeepsDevices(PwDatabase db)
		{
			return pendingOldKey != null && MatchesPending(db);
		}

		private static bool MatchesPending(PwDatabase db)
		{
			if (pendingCredentialId == null) return false;
			byte[] key = GetDatabaseKey(db);
			if (key == null) return false;
			try
			{
				return MemUtil.ArraysEqual(HashKey(key), pendingKeyHash);
			}
			finally
			{
				MemUtil.ZeroByteArray(key);
			}
		}

		/// <summary>Default device label: type by transport and credential creation time</summary>
		private static string DefaultLabel(uint transport)
		{
			return $"{WebAuthnHelper.TransportName(transport)}, {DateTime.Now:dd.MM.yyyy HH:mm}";
		}

		/// <summary>
		/// If the database master key is the key of the last created credential, adds its record
		/// to PublicCustomData (when keeping devices, re-wraps their keys for the new key).
		/// Returns true if the record was added.
		/// </summary>
		public static bool RegisterPendingDevice(PwDatabase db)
		{
			if (!MatchesPending(db)) return false;

			List<DeviceRecord> records = DeviceKeyStore.Load(db);
			if (pendingOldKey != null)
			{
				byte[] key = GetDatabaseKey(db);
				try
				{
					DeviceKeyStore.Rewrap(records, pendingOldKey, key);
					RewrapRecovery(db, pendingOldKey, key);
				}
				finally
				{
					MemUtil.ZeroByteArray(key);
				}
			}

			records.Add(new DeviceRecord
			{
				CredentialId = pendingCredentialId,
				WrappedKey = pendingWrappedKey,
				Label = pendingLabel
			});
			DeviceKeyStore.Save(db, records);

			if (pendingOldKey != null) MemUtil.ZeroByteArray(pendingOldKey);
			pendingOldKey = null;
			pendingCredentialId = null;
			pendingWrappedKey = null;
			pendingKeyHash = null;
			pendingLabel = null;
			return true;
		}

		/// <summary>
		/// Database key rotation: a new random K is re-wrapped for all records and the recovery phrase and substituted
		/// into the database master key (other master key components are kept). No authenticators needed.
		/// The database must be saved afterwards.
		/// </summary>
		public static void RotateDatabaseKey(PwDatabase db, List<DeviceRecord> records)
		{
			byte[] oldKey = GetDatabaseKey(db);
			if (oldKey == null)
				throw new InvalidOperationException("The database master key does not use FIDO2");

			byte[] newKey = GenerateKey();
			try
			{
				DeviceKeyStore.Rewrap(records, oldKey, newKey);
				RewrapRecovery(db, oldKey, newKey);

				var masterKey = new CompositeKey();
				foreach (IUserKey userKey in db.MasterKey.UserKeys)
					masterKey.AddUserKey(IsOurKey(userKey) ? new KcpCustomKey(ProviderName, newKey, false) : userKey);

				db.MasterKey = masterKey;
				db.MasterKeyChanged = DateTime.UtcNow;
				db.MasterKeyChangeForceOnce = false;
			}
			finally
			{
				MemUtil.ZeroByteArray(oldKey);
				MemUtil.ZeroByteArray(newKey);
			}
		}

		private static void RewrapRecovery(PwDatabase db, byte[] oldKey, byte[] newKey)
		{
			byte[] wrappedKey = DeviceKeyStore.LoadRecovery(db);
			if (wrappedKey == null) return;
			DeviceKeyStore.Rewrap(wrappedKey, oldKey, newKey);
			DeviceKeyStore.SaveRecovery(db, wrappedKey);
		}

		/// <summary>
		/// Database key K from the master key (our provider's KcpCustomKey), otherwise null
		/// </summary>
		public static byte[] GetDatabaseKey(PwDatabase db)
		{
			return FindOurKey(db)?.KeyData.ReadData();
		}

		public static bool UsesFido2Key(PwDatabase db)
		{
			return FindOurKey(db) != null;
		}

		private static KcpCustomKey FindOurKey(PwDatabase db)
		{
			if (db?.MasterKey == null) return null;
			foreach (IUserKey userKey in db.MasterKey.UserKeys)
			{
				if (IsOurKey(userKey)) return (KcpCustomKey)userKey;
			}
			return null;
		}

		private static bool IsOurKey(IUserKey userKey)
		{
			return userKey is KcpCustomKey custom && custom.Name == ProviderName;
		}

		private static byte[] GenerateKey()
		{
			byte[] key = new byte[DeviceKeyStore.KeyLength];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(key);
			return key;
		}

		private static byte[] HashKey(byte[] key)
		{
			using (var sha = SHA256.Create())
				return sha.ComputeHash(key);
		}

		/// <summary>
		/// Creates a credential with PRF for the database and returns credential ID + PRF secret
		/// (used both when creating the key and when adding a device)
		/// </summary>
		public static PrfResult CreateCredentialForDatabase(IntPtr windowHandle, string databasePath)
		{
			// User ID (32 bytes) is random so that each database/device gets a separate credential
			byte[] userId = new byte[32];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(userId);

			// Database name goes into the user entity and is visible in Windows/phone dialogs
			string dbName = string.IsNullOrEmpty(databasePath)
				? "KeePass Database"
				: System.IO.Path.GetFileName(databasePath);

			try
			{
				// displayName = full path: cleanup in Tools → KeePassPasskeyKeyProvider uses it to find credentials of deleted databases
				PrfResult created = WebAuthnHelper.CreateCredential(windowHandle, userId, $"KeePass: {dbName}", databasePath);

				// PRF secret: on API 8+ already obtained at creation, otherwise via a separate GetAssertion
				if (created.PrfSecret == null)
				{
					System.Threading.Thread.Sleep(500);
					created.PrfSecret = WebAuthnHelper.GetPrfSecret(windowHandle, new[] { created.CredentialId }).PrfSecret;
				}
				return created;
			}
			finally
			{
				MemUtil.ZeroByteArray(userId);
			}
		}

		/// <summary>
		/// Unlocks the database with a device; if WebAuthn is unavailable or authentication fails,
		/// offers the recovery phrase (if there is one)
		/// </summary>
		private static byte[] Unlock(KeyProviderQueryContext ctx)
		{
			List<DeviceRecord> records = LoadRecords(ctx);
			if (records == null)
				return null;

			string problem;
			if (!WebAuthnHelper.IsWebAuthnAvailable())
				problem = WebAuthnUnavailableMessage;
			else
			{
				try
				{
					return UnlockWithCredential(records);
				}
				catch (WebAuthnException ex)
				{
					problem = $"FIDO2 authentication error:\n{ex.Message}";
				}
			}
			return UnlockWithRecoveryPhrase(ctx, problem);
		}

		/// <summary>K = (K ⊕ R) ⊕ R, where R is the secret of the entered phrase. KeePass itself rejects a wrong phrase.</summary>
		private static byte[] UnlockWithRecoveryPhrase(KeyProviderQueryContext ctx, string problem)
		{
			byte[] wrappedKey = null;
			try { wrappedKey = DeviceKeyStore.LoadRecoveryFromFile(ctx.DatabaseIOInfo); }
			catch { /* a corrupted phrase record is not offered */ }

			if (wrappedKey == null)
			{
				MessageService.ShowWarning(problem);
				return null;
			}

			if (!MessageService.AskYesNo(problem + "\n\nOpen the database with the recovery phrase?", "KeePassPasskeyKeyProvider"))
				return null;

			var form = new RecoveryPhraseInputForm();
			if (UIUtil.ShowDialogAndDestroy(form) != DialogResult.OK)
				return null;

			byte[] secret = RecoveryPhrase.DeriveSecret(form.Entropy);
			try
			{
				return DeviceKeyStore.Wrap(wrappedKey, secret);
			}
			finally
			{
				MemUtil.ZeroByteArray(secret);
				MemUtil.ZeroByteArray(form.Entropy);
			}
		}

		/// <summary>
		/// Unlocks the database with a device: GetAssertion with the records' allowList → K = wrapped key ⊕ PRF
		/// </summary>
		private static byte[] UnlockWithCredential(List<DeviceRecord> records)
		{
			PrfResult assertion = WebAuthnHelper.GetPrfSecret(GetActiveWindowHandle(), DeviceKeyStore.GetAllowList(records));
			try
			{
				DeviceRecord record = DeviceKeyStore.Find(records, assertion.CredentialId);
				if (record == null)
					throw new WebAuthnException("The authenticator presented a credential not registered in this database");

				return DeviceKeyStore.Wrap(record.WrappedKey, assertion.PrfSecret);
			}
			finally
			{
				MemUtil.ZeroByteArray(assertion.CredentialId);
				MemUtil.ZeroByteArray(assertion.PrfSecret);
			}
		}

		/// <summary>
		/// Device records from the file header; null (with a message) if there are none or reading failed —
		/// the database cannot be opened without them
		/// </summary>
		private static List<DeviceRecord> LoadRecords(KeyProviderQueryContext ctx)
		{
			string problem;
			try
			{
				List<DeviceRecord> records = ctx.DatabaseIOInfo == null
					? new List<DeviceRecord>()
					: DeviceKeyStore.LoadFromFile(ctx.DatabaseIOInfo);
				if (records.Count > 0)
					return records;
				problem = "The database header has no FIDO2 device records (the database was not saved after creating the key " +
				          "or was created by an incompatible plugin version).";
			}
			catch (Exception ex)
			{
				problem = "Failed to read device records from the database header:\n" + ex.Message;
			}

			MessageService.ShowWarning(problem, "This plugin cannot open the database.");
			return null;
		}

		/// <summary>
		/// Gets the active window handle
		/// </summary>
		private static IntPtr GetActiveWindowHandle()
		{
			// Try to get the KeePass main window
			var mainForm = Form.ActiveForm ?? Application.OpenForms[0];
			return mainForm?.Handle ?? IntPtr.Zero;
		}

		public override string Name => ProviderName;

		// WebAuthn API works only in an interactive user session
		public override bool SecureDesktopCompatible => false;

		// PRF returns a 32-byte key that is already cryptographically strong
		// No additional hashing required
		public override bool DirectKey => true;
	}
}
