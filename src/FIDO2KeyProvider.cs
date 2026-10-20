using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskeyKeyProvider.Browser;
using KeePassPasskeyKeyProvider.Fido2;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// KeePass Key Provider using FIDO2 authentication with the PRF extension (WebAuthn Level 3): via the Windows
	/// WebAuthn API on Windows; elsewhere a USB security key through libfido2 or the system browser (see
	/// <see cref="UnlockWays"/>, <see cref="DeviceKind"/>).
	/// Database key K is 32 random bytes; the KDBX header (PublicCustomData) stores K wrapped
	/// for each device, signed with the database signing key (see <see cref="DeviceKeyStore"/>, <see cref="KeyWrap"/>).
	/// Credentials are discoverable: no files next to the database. Removing a device = rotation of K: the new K is
	/// wrapped for the remaining devices and the recovery phrase without the authenticators.
	/// </summary>
	public class FIDO2KeyProvider : KeyProvider
	{
		public const string ProviderName = "Passkey Key Provider (Windows WebAuthn)";

		/// <summary>
		/// Way to the authenticators: on Windows the Windows WebAuthn API for devices of both kinds, elsewhere the
		/// system browser for portable devices only (browsers do not accept the RP ID of classic devices); a security key
		/// also opens databases through libfido2 there (see <see cref="UnlockWays"/>)
		/// </summary>
		internal static readonly bool UsesBrowser = !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

		/// <summary>
		/// Device created by the last GetKey(CreatingNewKey) call, SHA‑256 of its K and the signing key its owner tag
		/// is bound to (new, or the key of the database whose devices are kept). The database is not yet available
		/// at this point; the record is written by <see cref="RegisterPendingDevice"/> when database settings are
		/// shown or on FileCreated / MasterKeyChanged events.
		/// </summary>
		private static DeviceRecord pendingRecord;
		private static byte[] pendingKeyHash;
		private static SigningKey pendingSigningKey;

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
				return ctx.CreatingNewKey ? CreateNewCredential(ctx) : Unlock(ctx);
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
			if (!CanUse(DeviceKind.Portable))
			{
				MessageService.ShowWarning(Strings.WebAuthnUnavailable);
				return null;
			}

			PwDatabase current = FindOpenDatabase(ctx);
			SigningKey currentSigningKey = null;
			try
			{
				// Devices can be kept only together with the signing key their owner tags are bound to
				DeviceRecordSet set = new DeviceRecordSet();
				List<DeviceRecord> existing = new List<DeviceRecord>();
				if (UsesFido2Key(current))
				{
					set = LoadRecordsSafe(current);
					currentSigningKey = DeviceKeyStore.LoadSigningKey(current, set.VerificationKey);
					if (currentSigningKey != null) existing = set.Devices;
				}

				var form = new DeviceNameForm(existing.ConvertAll(r => r.Label), UsesBrowser);
				if (UIUtil.ShowDialogAndDestroy(form) != DialogResult.OK)
					return null;
				// The new device of an existing database is portable: unless its records are v5 already, plugin versions
				// before portable devices cannot open the database afterwards (a new database has no such readers)
				if (current != null && !DeviceMigration.ConfirmVersion5(GetActiveForm(), set))
					return null;
				string label = form.DeviceName;
				bool keepDevices = form.KeepDevices && currentSigningKey != null && existing.Count > 0;

				PrfResult created = CreateCredentialForDatabase(GetActiveForm(), ctx.DatabasePath, existing);
				SigningKey signingKey = keepDevices ? currentSigningKey.Clone() : SigningKey.Generate();
				byte[] key = GenerateKey();
				try
				{
					var record = new DeviceRecord
					{
						Kind = DeviceKind.Portable,
						CredentialId = created.CredentialId,
						Wrap = KeyWrap.Create(key, created.PrfSecret, signingKey.VerificationKey),
						Label = label.Length > 0 ? label : DefaultLabel(created.Transport)
					};
					SetPending(record, HashKey(key), signingKey, keepDevices);
					signingKey = null;
					return key;
				}
				catch
				{
					MemUtil.ZeroByteArray(key);
					throw;
				}
				finally
				{
					signingKey?.Dispose();
					MemUtil.ZeroByteArray(created.PrfSecret);
				}
			}
			finally
			{
				currentSigningKey?.Dispose();
			}
		}

		private static void SetPending(DeviceRecord record, byte[] keyHash, SigningKey signingKey, bool keepDevices)
		{
			pendingSigningKey?.Dispose();
			pendingRecord = record;
			pendingKeyHash = keyHash;
			pendingSigningKey = signingKey;
			pendingKeepDevices = keepDevices;
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

		private static DeviceRecordSet LoadRecordsSafe(PwDatabase db)
		{
			try { return DeviceKeyStore.LoadAll(db); }
			catch { return new DeviceRecordSet(); } // corrupted records cannot be kept anyway
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
			// A browser passkey of this computer is in the passkey manager of the browser or system, not in Windows Hello
			string type = UsesBrowser && (transport & WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_INTERNAL) != 0
				? Strings.TransportThisComputer
				: WebAuthnHelper.TransportName(transport);
			return $"{type} ({Environment.MachineName}), {DateTime.Now.ToString("g")}";
		}

		/// <summary>
		/// If the database master key is the key of the last created credential, adds its record
		/// to PublicCustomData (when keeping devices, re-wraps the key for them and the phrase; otherwise
		/// replaces all records and the signing key). Returns true if the record was added.
		/// </summary>
		public static bool RegisterPendingDevice(PwDatabase db)
		{
			if (!MatchesPending(db)) return false;

			DeviceRecordSet set = pendingKeepDevices ? DeviceKeyStore.LoadAll(db) : new DeviceRecordSet();
			// The kept records must be bound to the signing key the pending tag was computed with
			if (set.VerificationKey == null || !MemUtil.ArraysEqual(set.VerificationKey, pendingSigningKey.VerificationKey))
				set = new DeviceRecordSet();
			else
			{
				byte[] key = GetDatabaseKey(db);
				try
				{
					Seal(set, key);
				}
				finally
				{
					MemUtil.ZeroByteArray(key);
				}
			}

			set.VerificationKey = pendingSigningKey.VerificationKey;
			set.Devices.Add(pendingRecord);
			DeviceKeyStore.SetSigningKey(db, pendingSigningKey);
			DeviceKeyStore.Save(db, set);

			SetPending(null, null, null, false);
			return true;
		}

		/// <summary>
		/// Database key rotation: a new random K is wrapped for all records and the recovery phrase, the records are
		/// written to the database, and K is substituted into the database master key (other master key components
		/// are kept). No authenticators needed. The signing key stays the same (see <see cref="DeviceKeyStore"/>).
		/// The database must be saved afterwards.
		/// </summary>
		public static void RotateDatabaseKey(PwDatabase db, DeviceRecordSet set)
		{
			if (!UsesFido2Key(db))
				throw new InvalidOperationException(Strings.MasterKeyNotFido2);

			byte[] newKey = GenerateKey();
			try
			{
				Seal(set, newKey);
				// Written before the master key changes: if writing fails, the database keeps a consistent state
				DeviceKeyStore.Save(db, set);

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

		/// <summary>
		/// Makes a classic device portable: its record keeps its position and label and gets the credential of a new
		/// portable passkey on the same authenticator, with the database key wrapped for its secret; the records are
		/// written to the database. K does not change: the owner is the same device (a lost device is removed instead,
		/// which rotates K). The database must be saved afterwards.
		/// </summary>
		public static void ReplaceWithPortable(PwDatabase db, DeviceRecordSet set, int index, PrfResult created)
		{
			DeviceRecord old = set.Devices[index];
			if (old.Kind != DeviceKind.Classic)
				throw new InvalidOperationException("The device is not classic");

			byte[] key = GetDatabaseKey(db);
			if (key == null)
				throw new InvalidOperationException(Strings.MasterKeyNotFido2);
			try
			{
				set.Devices[index] = new DeviceRecord
				{
					Kind = DeviceKind.Portable,
					CredentialId = created.CredentialId,
					Wrap = KeyWrap.Create(key, created.PrfSecret, set.VerificationKey),
					Label = old.Label
				};
			}
			finally
			{
				MemUtil.ZeroByteArray(key);
			}
			DeviceKeyStore.Save(db, set);
		}

		/// <summary>Wraps the key for the device records and the recovery phrase (in place)</summary>
		private static void Seal(DeviceRecordSet set, byte[] key)
		{
			foreach (DeviceRecord r in set.Devices)
				r.Wrap.Seal(key);
			set.Recovery?.Seal(key);
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
		/// Creates a credential with PRF for a new device of the database (always <see cref="DeviceKind.Portable"/>)
		/// and returns credential ID + PRF secret (used both when creating the key and when adding a device)
		/// </summary>
		/// <param name="existing">Devices of the database: the browser does not register an authenticator twice</param>
		public static PrfResult CreateCredentialForDatabase(Form owner, string databasePath, List<DeviceRecord> existing)
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
				// The credential will protect the database: the browser's result is accepted only with the code shown in KeePass
				if (UsesBrowser)
					return BrowserWebAuthn.CreateCredential(owner, userId, $"KeePass: {dbName}",
						DeviceKeyStore.GetAllowList(existing, DeviceKind.Portable), DatabaseName(databasePath), true);

				// displayName = full path: cleanup in Tools → KeePassPasskeyKeyProvider uses it to find credentials of deleted databases
				IntPtr windowHandle = owner?.Handle ?? IntPtr.Zero;
				PrfResult created = WebAuthnHelper.CreateCredential(windowHandle, DeviceKind.Portable, userId,
					$"KeePass: {dbName}", databasePath);

				// PRF secret: on API 8+ already obtained at creation, otherwise via a separate GetAssertion
				if (created.PrfSecret == null)
				{
					System.Threading.Thread.Sleep(500);
					created.PrfSecret = WebAuthnHelper.GetPrfSecret(windowHandle, DeviceKind.Portable,
						new[] { created.CredentialId }).PrfSecret;
				}
				return created;
			}
			finally
			{
				MemUtil.ZeroByteArray(userId);
			}
		}

		/// <summary>
		/// Whether devices of the kind can be added and used on this system (outside Windows a classic device that is
		/// a security key also opens a database, see <see cref="UnlockWays"/>)
		/// </summary>
		internal static bool CanUse(DeviceKind kind)
		{
			return UsesBrowser ? kind == DeviceKind.Portable : WebAuthnHelper.IsWebAuthnAvailable();
		}

		/// <summary>Way to the authenticators when unlocking</summary>
		private enum Way
		{
			/// <summary>Windows WebAuthn API</summary>
			WebAuthn,

			/// <summary>Connected USB security key through libfido2: no dialog if none of them holds a device</summary>
			SecurityKey,

			/// <summary>System browser</summary>
			Browser
		}

		/// <summary>
		/// Unlock order. Windows: the Windows WebAuthn API for portable, then for classic devices (each kind is one
		/// dialog). Elsewhere: a connected security key that holds a device of either kind (the only way for classic
		/// devices), then the browser for portable devices.
		/// </summary>
		private static readonly (Way Way, DeviceKind[] Kinds)[] UnlockWays = UsesBrowser
			? new[] { (Way.SecurityKey, new[] { DeviceKind.Portable, DeviceKind.Classic }), (Way.Browser, new[] { DeviceKind.Portable }) }
			: new[] { (Way.WebAuthn, new[] { DeviceKind.Portable }), (Way.WebAuthn, new[] { DeviceKind.Classic }) };

		/// <summary>
		/// Unlocks the database with a device in the order of <see cref="UnlockWays"/>; a way without devices is skipped.
		/// If authentication fails or the records are not authentic, offers the next way, then the recovery phrase
		/// (if there is one).
		/// </summary>
		private static byte[] Unlock(KeyProviderQueryContext ctx)
		{
			DeviceRecordSet set = LoadRecords(ctx);
			if (set == null)
				return null;

			string databaseName = DatabaseName(ctx.DatabasePath);
			string problem = null;
			bool failed = false;
			foreach ((Way way, DeviceKind[] kinds) in UnlockWays)
			{
				if (!set.Devices.Exists(r => Array.IndexOf(kinds, r.Kind) >= 0))
					continue;
				if (!IsAvailable(way))
				{
					problem = problem ?? Unavailable(way, set);
					continue;
				}
				if (failed && !MessageService.AskYesNo(problem + "\n\n" + Strings.TryOtherDevicesQuestion, "KeePassPasskeyKeyProvider"))
					break;

				byte[] key = TryUnlock(set, way, kinds, databaseName, out string reason, out bool asked, out DeviceRecord device);
				if (key != null)
				{
					if (device.Kind == DeviceKind.Classic)
						PortableReminder.Expect(ctx.DatabaseIOInfo, device.CredentialId);
					return key;
				}
				if (asked)
				{
					problem = reason;
					failed = true;
				}
				else
					problem = problem ?? reason;
			}
			return UnlockWithRecoveryPhrase(set, problem);
		}

		private static bool IsAvailable(Way way)
		{
			switch (way)
			{
				case Way.WebAuthn: return WebAuthnHelper.IsWebAuthnAvailable();
				case Way.SecurityKey: return Fido2Authenticator.IsAvailable;
				default: return true;
			}
		}

		/// <summary>Why devices cannot be used without the way; null if no word is needed</summary>
		private static string Unavailable(Way way, DeviceRecordSet set)
		{
			if (way == Way.WebAuthn)
				return Strings.WebAuthnUnavailable;
			// Without libfido2 portable devices still work in the browser
			return set.Devices.Exists(r => r.Kind == DeviceKind.Classic) ? ClassicDevicesProblem(Strings.Fido2LibraryMissing) : null;
		}

		/// <summary>Classic devices outside Windows: only a security key among them works</summary>
		private static string ClassicDevicesProblem(string reason) => reason + "\n\n" + Strings.ClassicDevicesElsewhere;

		/// <summary>K from a device of the kinds; null and the reason if authentication failed or the records are not authentic</summary>
		/// <param name="asked">
		/// The user took part; false if no connected security key holds a device (the reason is then about classic devices, or null)
		/// </param>
		/// <param name="device">Record of the device that gave K</param>
		private static byte[] TryUnlock(DeviceRecordSet set, Way way, DeviceKind[] kinds, string databaseName, out string problem,
			out bool asked, out DeviceRecord device)
		{
			problem = null;
			asked = true;
			device = null;
			try
			{
				Form owner = GetActiveForm();
				Fido2Exception notFound = null;
				foreach (DeviceKind kind in kinds)
				{
					List<DeviceRecord> devices = set.Devices.FindAll(r => r.Kind == kind);
					if (devices.Count == 0)
						continue;
					List<byte[]> allowList = DeviceKeyStore.GetAllowList(devices, kind);
					PrfResult assertion;
					switch (way)
					{
						case Way.WebAuthn:
							assertion = WebAuthnHelper.GetPrfSecret(owner?.Handle ?? IntPtr.Zero, kind, allowList);
							break;
						case Way.Browser:
							assertion = BrowserWebAuthn.GetPrfSecret(owner, allowList, databaseName);
							break;
						default:
							try
							{
								assertion = SecurityKeyPrompt.GetPrfSecret(owner, WebAuthnHelper.RpId(kind), allowList);
							}
							catch (Fido2Exception ex) when (ex.KeyNotFound)
							{
								notFound = ex;
								continue;
							}
							break;
					}
					return UnlockWithCredential(set, devices, assertion, out device);
				}

				asked = false;
				if (set.Devices.Exists(r => r.Kind == DeviceKind.Classic))
					problem = ClassicDevicesProblem(notFound?.Message);
			}
			catch (WebAuthnException ex)
			{
				problem = AuthenticationError(ex);
			}
			catch (CryptographicException)
			{
				// The device secret does not match the owner tag for VK, or the signature is invalid
				problem = Strings.RecordsNotAuthentic;
			}
			return null;
		}

		/// <summary>K unwrapped with the secret R of the entered phrase</summary>
		private static byte[] UnlockWithRecoveryPhrase(DeviceRecordSet set, string problem)
		{
			if (set.Recovery == null)
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
			byte[] key;
			try
			{
				key = set.Recovery.Open(secret, set.VerificationKey);
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

			try
			{
				return Authenticated(set, key);
			}
			catch (CryptographicException)
			{
				MessageService.ShowWarning(Strings.RecordsNotAuthentic);
				return null;
			}
		}

		/// <summary>K from the PRF secret of a device: the wrap of its record, opened with the secret</summary>
		/// <exception cref="CryptographicException">The records are not authentic</exception>
		private static byte[] UnlockWithCredential(DeviceRecordSet set, List<DeviceRecord> devices, PrfResult assertion,
			out DeviceRecord record)
		{
			byte[] key;
			try
			{
				record = DeviceKeyStore.Find(devices, assertion.CredentialId);
				if (record == null)
					throw new WebAuthnException(Strings.UnknownCredential);

				key = record.Wrap.Open(assertion.PrfSecret, set.VerificationKey);
			}
			finally
			{
				MemUtil.ZeroByteArray(assertion.CredentialId);
				MemUtil.ZeroByteArray(assertion.PrfSecret);
			}
			return Authenticated(set, key);
		}

		/// <summary>
		/// K after the owner tag check, if the records are signed with the key the tag is bound to; otherwise the key is wiped
		/// </summary>
		/// <exception cref="CryptographicException">Invalid signature</exception>
		private static byte[] Authenticated(DeviceRecordSet set, byte[] key)
		{
			if (set.VerifySignature())
				return key;

			MemUtil.ZeroByteArray(key);
			throw new CryptographicException("Invalid signature of the device records");
		}

		/// <summary>
		/// Device records from the file header; null (with a message) if there are none or reading failed —
		/// the database cannot be opened without them
		/// </summary>
		private static DeviceRecordSet LoadRecords(KeyProviderQueryContext ctx)
		{
			string problem;
			try
			{
				DeviceRecordSet set = ctx.DatabaseIOInfo == null
					? new DeviceRecordSet()
					: DeviceKeyStore.LoadAllFromFile(ctx.DatabaseIOInfo);
				if (set.Devices.Count > 0)
					return set;
				problem = Strings.NoDeviceRecords;
			}
			catch (Exception ex)
			{
				problem = string.Format(Strings.ReadHeaderRecordsFailed, ex.Message);
			}

			MessageService.ShowWarning(problem, Strings.CannotOpenDatabase);
			return null;
		}

		/// <summary>File name of the database for dialogs; null if there is no path</summary>
		private static string DatabaseName(string databasePath)
		{
			return string.IsNullOrEmpty(databasePath) ? null : System.IO.Path.GetFileName(databasePath);
		}

		/// <summary>Active window (the key prompt) or the KeePass main window: owner of the authentication dialogs</summary>
		private static Form GetActiveForm()
		{
			return Form.ActiveForm ?? (Application.OpenForms.Count > 0 ? Application.OpenForms[0] : null);
		}

		public override string Name => ProviderName;

		// WebAuthn API works only in an interactive user session
		public override bool SecureDesktopCompatible => false;

		// K is 32 random bytes: used as is, no additional hashing required
		public override bool DirectKey => true;
	}
}
