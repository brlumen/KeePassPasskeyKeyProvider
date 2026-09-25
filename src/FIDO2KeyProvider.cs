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
	/// Database key K is 32 random bytes; the KDBX header (PublicCustomData) stores K wrapped
	/// for each device (see <see cref="DeviceKeyStore"/>, <see cref="KeyWrap"/>). Credentials are discoverable:
	/// no files next to the database. Removing a device = rotation of K: the new K is wrapped for the remaining
	/// devices and the recovery phrase without the authenticators.
	/// </summary>
	public class FIDO2KeyProvider : KeyProvider
	{
		public const string ProviderName = "Passkey Key Provider (Windows WebAuthn)";

		/// <summary>
		/// Device created by the last GetKey(CreatingNewKey) call and SHA‑256 of its K. The database is not yet
		/// available at this point; the record is written by <see cref="RegisterPendingDevice"/> when database
		/// settings are shown or on FileCreated / MasterKeyChanged events.
		/// </summary>
		private static DeviceRecord pendingRecord;
		private static byte[] pendingKeyHash;

		/// <summary>Master key change keeping the other devices: their K is re-wrapped for the new key</summary>
		private static bool pendingKeepDevices;

		private readonly IPluginHost host;

		public FIDO2KeyProvider(IPluginHost host)
		{
			this.host = host;
		}

		public override byte[] GetKey(KeyProviderQueryContext ctx)
		{
			try
			{
				if (!ctx.CreatingNewKey)
					return Unlock(ctx);

				if (!WebAuthnHelper.IsWebAuthnAvailable())
				{
					MessageService.ShowWarning(Strings.WebAuthnUnavailable);
					return null;
				}
				return CreateNewCredential(ctx);
			}
			catch (WebAuthnException ex)
			{
				MessageService.ShowWarning(AuthenticationError(ex));
				return null;
			}
			catch (Exception ex)
			{
				MessageService.ShowWarning(string.Format(Strings.UnexpectedError, ex.Message, ex.GetType().Name));
				return null;
			}
		}

		private static string AuthenticationError(WebAuthnException ex) =>
			string.Format(Strings.AuthenticationError, ex.Message);

		/// <summary>
		/// Creates a new credential and a random database key K; the device record awaits writing to the database.
		/// When changing the master key of an open database, the user chooses whether to keep its other devices.
		/// </summary>
		private byte[] CreateNewCredential(KeyProviderQueryContext ctx)
		{
			PwDatabase current = FindOpenDatabase(ctx);
			List<DeviceRecord> existing = UsesFido2Key(current) ? LoadRecordsSafe(current) : new List<DeviceRecord>();

			var form = new DeviceNameForm(existing.ConvertAll(r => r.Label));
			if (UIUtil.ShowDialogAndDestroy(form) != DialogResult.OK)
				return null;
			string label = form.DeviceName;

			PrfResult created = CreateCredentialForDatabase(GetActiveWindowHandle(), ctx.DatabasePath);
			try
			{
				byte[] key = GenerateKey();
				pendingRecord = new DeviceRecord
				{
					CredentialId = created.CredentialId,
					Wrap = KeyWrap.Create(key, created.PrfSecret),
					Label = label.Length > 0 ? label : DefaultLabel(created.Transport)
				};
				pendingKeyHash = HashKey(key);
				pendingKeepDevices = form.KeepDevices && existing.Count > 0;
				return key;
			}
			finally
			{
				MemUtil.ZeroByteArray(created.PrfSecret);
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
			return pendingKeepDevices && MatchesPending(db);
		}

		private static bool MatchesPending(PwDatabase db)
		{
			if (pendingRecord == null) return false;
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

		/// <summary>Default device label: type by transport, computer name and credential creation time</summary>
		private static string DefaultLabel(uint transport)
		{
			return $"{WebAuthnHelper.TransportName(transport)} ({Environment.MachineName}), {DateTime.Now:dd.MM.yyyy HH:mm}";
		}

		/// <summary>
		/// If the database master key is the key of the last created credential, adds its record
		/// to PublicCustomData (when keeping devices, re-wraps the key for them and the phrase).
		/// Returns true if the record was added.
		/// </summary>
		public static bool RegisterPendingDevice(PwDatabase db)
		{
			if (!MatchesPending(db)) return false;

			List<DeviceRecord> records = DeviceKeyStore.Load(db);
			if (pendingKeepDevices)
			{
				byte[] key = GetDatabaseKey(db);
				try
				{
					Seal(db, records, key);
				}
				finally
				{
					MemUtil.ZeroByteArray(key);
				}
			}

			records.Add(pendingRecord);
			DeviceKeyStore.Save(db, records);

			pendingRecord = null;
			pendingKeyHash = null;
			pendingKeepDevices = false;
			return true;
		}

		/// <summary>
		/// Database key rotation: a new random K is wrapped for all records and the recovery phrase and substituted
		/// into the database master key (other master key components are kept). No authenticators needed.
		/// The database must be saved afterwards.
		/// </summary>
		public static void RotateDatabaseKey(PwDatabase db, List<DeviceRecord> records)
		{
			if (!UsesFido2Key(db))
				throw new InvalidOperationException(Strings.MasterKeyNotFido2);

			byte[] newKey = GenerateKey();
			try
			{
				Seal(db, records, newKey);

				var masterKey = new CompositeKey();
				foreach (IUserKey userKey in db.MasterKey.UserKeys)
					masterKey.AddUserKey(IsOurKey(userKey) ? new KcpCustomKey(ProviderName, newKey, false) : userKey);

				db.MasterKey = masterKey;
				db.MasterKeyChanged = DateTime.UtcNow;
				db.MasterKeyChangeForceOnce = false;
			}
			finally
			{
				MemUtil.ZeroByteArray(newKey);
			}
		}

		/// <summary>Wraps the key for the records (in place) and the recovery phrase (written to the database)</summary>
		private static void Seal(PwDatabase db, List<DeviceRecord> records, byte[] key)
		{
			foreach (DeviceRecord r in records)
				r.Wrap.Seal(key);

			KeyWrap recovery = DeviceKeyStore.LoadRecovery(db);
			if (recovery == null) return;
			recovery.Seal(key);
			DeviceKeyStore.SaveRecovery(db, recovery);
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
			byte[] key = new byte[KeyWrap.KeyLength];
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
				problem = Strings.WebAuthnUnavailable;
			else
			{
				try
				{
					return UnlockWithCredential(records);
				}
				catch (WebAuthnException ex)
				{
					problem = AuthenticationError(ex);
				}
			}
			return UnlockWithRecoveryPhrase(ctx, problem);
		}

		/// <summary>K unwrapped with the secret R of the entered phrase</summary>
		private static byte[] UnlockWithRecoveryPhrase(KeyProviderQueryContext ctx, string problem)
		{
			KeyWrap recovery = null;
			try { recovery = DeviceKeyStore.LoadRecoveryFromFile(ctx.DatabaseIOInfo); }
			catch { /* a corrupted phrase record is not offered */ }

			if (recovery == null)
			{
				MessageService.ShowWarning(problem);
				return null;
			}

			if (!MessageService.AskYesNo(problem + "\n\n" + Strings.OpenWithRecoveryPhrase, "KeePassPasskeyKeyProvider"))
				return null;

			var form = new RecoveryPhraseInputForm();
			if (UIUtil.ShowDialogAndDestroy(form) != DialogResult.OK)
				return null;

			byte[] secret = RecoveryPhrase.DeriveSecret(form.Entropy);
			try
			{
				return recovery.Open(secret);
			}
			catch (CryptographicException)
			{
				MessageService.ShowWarning(Strings.RecoveryPhraseMismatch);
				return null;
			}
			finally
			{
				MemUtil.ZeroByteArray(secret);
				MemUtil.ZeroByteArray(form.Entropy);
			}
		}

		/// <summary>
		/// Unlocks the database with a device: GetAssertion with the records' allowList → PRF → K
		/// </summary>
		private static byte[] UnlockWithCredential(List<DeviceRecord> records)
		{
			PrfResult assertion = WebAuthnHelper.GetPrfSecret(GetActiveWindowHandle(), DeviceKeyStore.GetAllowList(records));
			try
			{
				DeviceRecord record = DeviceKeyStore.Find(records, assertion.CredentialId);
				if (record == null)
					throw new WebAuthnException(Strings.UnknownCredential);

				return record.Wrap.Open(assertion.PrfSecret);
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
				problem = Strings.NoDeviceRecords;
			}
			catch (Exception ex)
			{
				problem = string.Format(Strings.ReadHeaderRecordsFailed, ex.Message);
			}

			MessageService.ShowWarning(problem, Strings.CannotOpenDatabase);
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
