using System;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePassFIDO2.WebAuthn;
using KeePassLib.Keys;
using KeePassLib.Utility;

namespace KeePassFIDO2
{
	/// <summary>
	/// Key Provider для KeePass, использующий FIDO2 аутентификацию через Windows WebAuthn API
	/// с поддержкой PRF extension (WebAuthn Level 3) для детерминированной генерации ключей
	/// </summary>
	public class FIDO2KeyProvider : KeyProvider
	{
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
				if (ctx.CreatingNewKey)
				{
					return CreateNewCredential(ctx);
				}
				else
				{
					return UnlockWithCredential(ctx);
				}
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
		/// Создает новый credential и сохраняет его
		/// </summary>
		private byte[] CreateNewCredential(KeyProviderQueryContext ctx)
		{
			// Генерируем User ID (32 байта)
			byte[] userId = new byte[32];
			using (var rng = new RNGCryptoServiceProvider())
			{
				rng.GetBytes(userId);
			}

			// Показываем информационное сообщение
			var result = MessageBox.Show(
				"Сейчас будет создан новый FIDO2 credential для этой базы данных.\n\n" +
				"Вам потребуется:\n" +
				"1. Современный FIDO2 ключ с поддержкой PRF (YubiKey 5, Google Titan и др.)\n" +
				"2. Ввести PIN-код ключа\n" +
				"3. Подтвердить создание credential (обычно нажатием кнопки на ключе)\n\n" +
				"Credential ID будет сохранён в файл рядом с базой данных.\n\n" +
				"Примечание: используется PRF extension (WebAuthn Level 3).\n\n" +
				"Продолжить?",
				"Создание FIDO2 Credential",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Information);

			if (result != DialogResult.Yes)
			{
				return null;
			}

			// Получаем дескриптор окна
			IntPtr windowHandle = GetActiveWindowHandle();

			// Создаем credential; имя базы попадает в user entity и видно в диалогах Windows/телефона
			string dbName = string.IsNullOrEmpty(ctx.DatabasePath)
				? "KeePass Database"
				: System.IO.Path.GetFileName(ctx.DatabasePath);
			var created = WebAuthnHelper.CreateCredential(windowHandle, userId, $"KeePass: {dbName}");
			byte[] credentialId = created.CredentialId;

			// Сохраняем credential ID
			if (!string.IsNullOrEmpty(ctx.DatabasePath))
			{
				try
				{
					CredentialStorage.SaveCredentialId(ctx.DatabasePath, credentialId, userId);
					MessageService.ShowInfo(
						"FIDO2 credential с PRF успешно создан и сохранён!\n\n" +
						$"Файл: {System.IO.Path.GetFileNameWithoutExtension(ctx.DatabasePath)}.fido2\n\n" +
						"Сохраните этот файл вместе с базой данных.\n\n" +
						"Используется PRF extension (WebAuthn Level 3).");
				}
				catch (Exception ex)
				{
					MessageService.ShowWarning($"Не удалось сохранить credential ID:\n{ex.Message}");
					return null;
				}
			}

			// PRF secret: на API 8+ уже получен при создании, иначе — отдельный GetAssertion
			byte[] prfSecret = created.PrfSecret;
			if (prfSecret == null)
			{
				System.Threading.Thread.Sleep(500);
				prfSecret = WebAuthnHelper.GetPrfSecret(windowHandle, credentialId);
			}

			// Убираем из памяти чувствительные данные
			MemUtil.ZeroByteArray(userId);
			MemUtil.ZeroByteArray(credentialId);

			return prfSecret;
		}

		/// <summary>
		/// Разблокирует базу данных используя существующий credential
		/// </summary>
		private byte[] UnlockWithCredential(KeyProviderQueryContext ctx)
		{
			// Проверяем наличие сохраненного credential ID
			if (string.IsNullOrEmpty(ctx.DatabasePath))
			{
				MessageService.ShowWarning("Невозможно определить путь к базе данных.");
				return null;
			}

			if (!CredentialStorage.CredentialExists(ctx.DatabasePath))
			{
				MessageService.ShowWarning(
					"Файл с FIDO2 credential не найден.\n\n" +
					"Убедитесь, что файл .fido2 находится в той же папке, что и база данных.\n\n" +
					"Если вы впервые используете FIDO2 для этой базы данных, " +
					"создайте новую базу с использованием FIDO2 в качестве ключа.");
				return null;
			}

			// Загружаем credential ID
			var credentialData = CredentialStorage.LoadCredentialId(ctx.DatabasePath);
			if (!credentialData.HasValue)
			{
				MessageService.ShowWarning("Не удалось загрузить credential ID из файла.");
				return null;
			}

			byte[] credentialId = credentialData.Value.credentialId;
			byte[] userId = credentialData.Value.userId;

			try
			{
				// Получаем дескриптор окна
				IntPtr windowHandle = GetActiveWindowHandle();

				// Получаем PRF secret от аутентификатора
				byte[] prfSecret = WebAuthnHelper.GetPrfSecret(windowHandle, credentialId);

				// Убираем из памяти
				MemUtil.ZeroByteArray(credentialId);
				MemUtil.ZeroByteArray(userId);

				return prfSecret;
			}
			finally
			{
				// Гарантируем очистку памяти
				if (credentialId != null) MemUtil.ZeroByteArray(credentialId);
				if (userId != null) MemUtil.ZeroByteArray(userId);
			}
		}

		/// <summary>
		/// Получает дескриптор активного окна
		/// </summary>
		private IntPtr GetActiveWindowHandle()
		{
			// Пытаемся получить главное окно KeePass
			var mainForm = Form.ActiveForm ?? Application.OpenForms[0];
			return mainForm?.Handle ?? IntPtr.Zero;
		}

		public override string Name => "FIDO2 Key Provider (Windows WebAuthn)";
		
		// WebAuthn API работает только из интерактивного окружения пользователя
		public override bool SecureDesktopCompatible => false;
		
		// PRF возвращает 32-байтовый ключ, который уже является криптографически стойким
		// Не требуется дополнительное хеширование
		public override bool DirectKey => true;
	}
}
