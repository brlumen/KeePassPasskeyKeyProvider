using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassFIDO2.WebAuthn;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Utility;

namespace KeePassFIDO2
{
	/// <summary>
	/// Key Provider для KeePass, использующий FIDO2 аутентификацию через Windows WebAuthn API
	/// с поддержкой PRF extension (WebAuthn Level 3).
	/// Ключ базы K — случайные 32 байта; в заголовке KDBX (PublicCustomData) для каждого устройства
	/// хранится K ⊕ PRF_i (см. <see cref="DeviceKeyStore"/>). Credential — discoverable: файлов рядом с базой нет.
	/// Удаление устройства = ротация K: новый K перешифровывается для оставшихся устройств.
	/// </summary>
	public class FIDO2KeyProvider : KeyProvider
	{
		public const string ProviderName = "FIDO2 Key Provider (Windows WebAuthn)";

		/// <summary>
		/// Устройство, созданное последним вызовом GetKey(CreatingNewKey): credential ID, обёртка K ⊕ PRF,
		/// подпись и SHA‑256 ключа K. База в этот момент ещё недоступна; запись делает
		/// <see cref="RegisterPendingDevice"/> при показе параметров базы либо по событиям FileCreated / MasterKeyChanged.
		/// </summary>
		private static byte[] pendingCredentialId;
		private static byte[] pendingWrappedKey;
		private static byte[] pendingKeyHash;
		private static string pendingLabel;

		/// <summary>
		/// Смена мастер‑ключа с сохранением остальных устройств: прежний ключ базы, чтобы перешифровать
		/// их обёртки на новый K (как при ротации). null — остальные устройства удаляются.
		/// </summary>
		private static byte[] pendingOldKey;

		private readonly IPluginHost host;

		public FIDO2KeyProvider(IPluginHost host)
		{
			this.host = host;
		}

		public override byte[] GetKey(KeyProviderQueryContext ctx)
		{
			// Проверка доступности WebAuthn API
			if (!WebAuthnHelper.IsWebAuthnAvailable())
			{
				MessageService.ShowWarning(
					"Windows WebAuthn API недоступен.\n\n" +
					"Этот плагин требует Windows 10 22H2 или Windows 11 (WebAuthn API v4+).\n" +
					"Убедитесь, что ваша система соответствует минимальным требованиям.");
				return null;
			}

			try
			{
				return ctx.CreatingNewKey ? CreateNewCredential(ctx) : UnlockWithCredential(ctx);
			}
			catch (WebAuthnException ex)
			{
				MessageService.ShowWarning($"Ошибка FIDO2 аутентификации:\n{ex.Message}");
				return null;
			}
			catch (Exception ex)
			{
				MessageService.ShowWarning($"Неожиданная ошибка:\n{ex.Message}\n\nТип: {ex.GetType().Name}");
				return null;
			}
		}

		/// <summary>
		/// Создаёт новый credential и случайный ключ базы K; обёртка K ⊕ PRF ждёт записи в базу.
		/// При смене мастер‑ключа открытой базы пользователь выбирает, сохранить ли её остальные устройства.
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

		/// <summary>Открытая база, мастер‑ключ которой сейчас меняется; null для новой базы</summary>
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
			catch { return new List<DeviceRecord>(); } // повреждённые записи сохранить всё равно нельзя
		}

		/// <summary>
		/// Смена мастер‑ключа базы на ключ последнего созданного credential с сохранением остальных устройств
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

		/// <summary>Подпись устройства по умолчанию: тип по транспорту и момент создания credential</summary>
		private static string DefaultLabel(uint transport)
		{
			return $"{WebAuthnHelper.TransportName(transport)}, {DateTime.Now:dd.MM.yyyy HH:mm}";
		}

		/// <summary>
		/// Если мастер‑ключ базы — ключ последнего созданного credential, добавляет его запись
		/// в PublicCustomData (при сохранении устройств — перешифровав их обёртки на новый ключ).
		/// Возвращает true, если запись добавлена.
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
		/// Ротация ключа базы: новый случайный K перешифровывается для всех записей и подставляется
		/// в мастер‑ключ базы (остальные компоненты мастер‑ключа сохраняются). Аутентификаторы не нужны.
		/// Базу после этого необходимо сохранить.
		/// </summary>
		public static void RotateDatabaseKey(PwDatabase db, List<DeviceRecord> records)
		{
			byte[] oldKey = GetDatabaseKey(db);
			if (oldKey == null)
				throw new InvalidOperationException("Мастер‑ключ базы не использует FIDO2");

			byte[] newKey = GenerateKey();
			try
			{
				DeviceKeyStore.Rewrap(records, oldKey, newKey);

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

		/// <summary>
		/// Ключ базы K из мастер‑ключа (KcpCustomKey нашего провайдера), иначе null
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
		/// Создаёт credential с PRF для базы и возвращает credential ID + PRF‑секрет
		/// (используется и при создании ключа, и при добавлении устройства)
		/// </summary>
		public static PrfResult CreateCredentialForDatabase(IntPtr windowHandle, string databasePath)
		{
			// User ID (32 байта) — случайный, чтобы каждая база/устройство получали отдельный credential
			byte[] userId = new byte[32];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(userId);

			// Имя базы попадает в user entity и видно в диалогах Windows/телефона
			string dbName = string.IsNullOrEmpty(databasePath)
				? "KeePass Database"
				: System.IO.Path.GetFileName(databasePath);

			try
			{
				// displayName = полный путь: по нему очистка в Tools → KeePassFIDO2 находит credential удалённых баз
				PrfResult created = WebAuthnHelper.CreateCredential(windowHandle, userId, $"KeePass: {dbName}", databasePath);

				// PRF secret: на API 8+ уже получен при создании, иначе — отдельный GetAssertion
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
		/// Разблокирует базу: записи из заголовка → GetAssertion по allowList → K = обёртка ⊕ PRF
		/// </summary>
		private byte[] UnlockWithCredential(KeyProviderQueryContext ctx)
		{
			List<DeviceRecord> records = LoadRecords(ctx);
			if (records == null)
				return null;

			PrfResult assertion = WebAuthnHelper.GetPrfSecret(GetActiveWindowHandle(), DeviceKeyStore.GetAllowList(records));
			try
			{
				DeviceRecord record = DeviceKeyStore.Find(records, assertion.CredentialId);
				if (record == null)
					throw new WebAuthnException("Аутентификатор предъявил credential, не зарегистрированный в этой базе");

				return DeviceKeyStore.Wrap(record.WrappedKey, assertion.PrfSecret);
			}
			finally
			{
				MemUtil.ZeroByteArray(assertion.CredentialId);
				MemUtil.ZeroByteArray(assertion.PrfSecret);
			}
		}

		/// <summary>
		/// Записи устройств из заголовка файла; null (с сообщением), если их нет или прочитать не удалось —
		/// без них базу открыть нельзя
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
				problem = "В заголовке базы нет записей устройств FIDO2 (база не сохранена после создания ключа " +
				          "или создана несовместимой версией плагина).";
			}
			catch (Exception ex)
			{
				problem = "Не удалось прочитать записи устройств из заголовка базы:\n" + ex.Message;
			}

			MessageService.ShowWarning(problem, "Открыть базу этим плагином невозможно.");
			return null;
		}

		/// <summary>
		/// Получает дескриптор активного окна
		/// </summary>
		private static IntPtr GetActiveWindowHandle()
		{
			// Пытаемся получить главное окно KeePass
			var mainForm = Form.ActiveForm ?? Application.OpenForms[0];
			return mainForm?.Handle ?? IntPtr.Zero;
		}

		public override string Name => ProviderName;

		// WebAuthn API работает только из интерактивного окружения пользователя
		public override bool SecureDesktopCompatible => false;

		// PRF возвращает 32-байтовый ключ, который уже является криптографически стойким
		// Не требуется дополнительное хеширование
		public override bool DirectKey => true;
	}
}
