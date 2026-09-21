using System;
using System.Text;
using System.Windows.Forms;
using KeePassFIDO2.WebAuthn;

namespace KeePassFIDO2
{
	/// <summary>
	/// Форма для диагностики FIDO2 ключей и проверки поддержки PRF (Pseudo-Random Function)
	/// </summary>
	public partial class FIDO2DiagnosticsForm : Form
	{
		private TextBox txtLog;
		private Button btnTestHmacSecret;
		private Button btnCheckApiVersion;
		private Button btnClose;
		private StringBuilder logBuilder;

		public FIDO2DiagnosticsForm()
		{
			InitializeComponent();
			logBuilder = new StringBuilder();
		}

		private void InitializeComponent()
		{
			this.txtLog = new TextBox();
			this.btnTestHmacSecret = new Button();
			this.btnCheckApiVersion = new Button();
			this.btnClose = new Button();
			this.SuspendLayout();

			// txtLog
			this.txtLog.Anchor = ((AnchorStyles)((((AnchorStyles.Top | AnchorStyles.Bottom)
				| AnchorStyles.Left)
				| AnchorStyles.Right)));
			this.txtLog.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
			this.txtLog.Location = new System.Drawing.Point(12, 12);
			this.txtLog.Multiline = true;
			this.txtLog.Name = "txtLog";
			this.txtLog.ReadOnly = true;
			this.txtLog.ScrollBars = ScrollBars.Vertical;
			this.txtLog.Size = new System.Drawing.Size(660, 380);
			this.txtLog.TabIndex = 0;

			// btnCheckApiVersion
			this.btnCheckApiVersion.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
			this.btnCheckApiVersion.Location = new System.Drawing.Point(12, 398);
			this.btnCheckApiVersion.Name = "btnCheckApiVersion";
			this.btnCheckApiVersion.Size = new System.Drawing.Size(150, 30);
			this.btnCheckApiVersion.TabIndex = 1;
			this.btnCheckApiVersion.Text = "Проверить API";
			this.btnCheckApiVersion.UseVisualStyleBackColor = true;
			this.btnCheckApiVersion.Click += new EventHandler(this.BtnCheckApiVersion_Click);

			// btnTestHmacSecret
			this.btnTestHmacSecret.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
			this.btnTestHmacSecret.Location = new System.Drawing.Point(168, 398);
			this.btnTestHmacSecret.Name = "btnTestHmacSecret";
			this.btnTestHmacSecret.Size = new System.Drawing.Size(180, 30);
			this.btnTestHmacSecret.TabIndex = 2;
			this.btnTestHmacSecret.Text = "Тест PRF";
			this.btnTestHmacSecret.UseVisualStyleBackColor = true;
			this.btnTestHmacSecret.Click += new EventHandler(this.BtnTestHmacSecret_Click);

			// btnClose
			this.btnClose.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Right)));
			this.btnClose.Location = new System.Drawing.Point(597, 398);
			this.btnClose.Name = "btnClose";
			this.btnClose.Size = new System.Drawing.Size(75, 30);
			this.btnClose.TabIndex = 3;
			this.btnClose.Text = "Закрыть";
			this.btnClose.UseVisualStyleBackColor = true;
			this.btnClose.Click += new EventHandler(this.BtnClose_Click);

			// FIDO2DiagnosticsForm
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(684, 440);
			this.Controls.Add(this.btnClose);
			this.Controls.Add(this.btnTestHmacSecret);
			this.Controls.Add(this.btnCheckApiVersion);
			this.Controls.Add(this.txtLog);
			this.MinimumSize = new System.Drawing.Size(600, 400);
			this.Name = "FIDO2DiagnosticsForm";
			this.StartPosition = FormStartPosition.CenterParent;
			this.Text = "FIDO2 Диагностика - Проверка поддержки PRF";
			this.Load += new EventHandler(this.FIDO2DiagnosticsForm_Load);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private void FIDO2DiagnosticsForm_Load(object sender, EventArgs e)
		{
			Log("=== FIDO2 Диагностика - PRF Extension ===");
			Log("");
			Log("Эта утилита поможет определить, поддерживает ли ваш FIDO2 ключ");
			Log("расширение PRF (Pseudo-Random Function) - WebAuthn Level 3.");
			Log("");
			Log("PRF - это современная замена hmac-secret, поддерживаемая новыми ключами.");
			Log("");
			Log("Шаги:");
			Log("1. Нажмите 'Проверить API' для проверки доступности WebAuthn API");
			Log("2. Нажмите 'Тест PRF' для создания тестового credential и проверки PRF");
			Log("");
			Log("Готов к тестированию.");
			Log("----------------------------------------");
			Log("");
		}

		private void BtnCheckApiVersion_Click(object sender, EventArgs e)
		{
			try
			{
				Log(">>> Проверка Windows WebAuthn API...");
				
				if (!WebAuthnHelper.IsWebAuthnAvailable())
				{
					Log("❌ ОШИБКА: WebAuthn API недоступен!");
					Log("   Требуется Windows 10 22H2 или Windows 11 (WebAuthn API v4+)");
					return;
				}

				Log("✓ WebAuthn API доступен");

				uint version = WebAuthnHelper.GetApiVersion();
				Log($"✓ Версия API: {version}");

				bool isPlatformAuthAvailable = false;
				int hr = WebAuthnApi.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out isPlatformAuthAvailable);
				
				if (hr == 0)
				{
					Log($"✓ Platform Authenticator: {(isPlatformAuthAvailable ? "Доступен (Windows Hello)" : "Недоступен")}");
				}
				else
				{
					Log($"⚠ Не удалось проверить Platform Authenticator (HRESULT: 0x{hr:X8})");
				}

				Log("");
				Log("Система готова к работе с FIDO2 ключами.");
				Log("----------------------------------------");
				Log("");
			}
			catch (Exception ex)
			{
				Log($"❌ ОШИБКА: {ex.Message}");
				Log($"   Тип: {ex.GetType().Name}");
				Log("----------------------------------------");
				Log("");
			}
		}

		private void BtnTestHmacSecret_Click(object sender, EventArgs e)
		{
			try
			{
				Log(">>> Начало теста PRF (Pseudo-Random Function)...");
				Log("");

				// Предупреждение пользователя
				var result = MessageBox.Show(
					"Сейчас будет создан ТЕСТОВЫЙ credential на вашем FIDO2 ключе.\n\n" +
					"Вам потребуется:\n" +
					"1. Вставить/подключить FIDO2 ключ\n" +
					"2. Ввести PIN-код ключа\n" +
					"3. Подтвердить создание (коснуться кнопки на ключе)\n\n" +
					"Этот тест НЕ повлияет на ваши существующие базы данных,\n" +
					"но тестовый credential останется на ключе (discoverable) — его можно удалить\n" +
					"в Параметры Windows → Учётные записи → Варианты входа → Ключ безопасности.\n\n" +
					"Продолжить тест?",
					"Тест PRF",
					MessageBoxButtons.YesNo,
					MessageBoxIcon.Question);

				if (result != DialogResult.Yes)
				{
					Log("Тест отменён пользователем.");
					Log("----------------------------------------");
					Log("");
					return;
				}

				Log("Шаг 1: Создание тестового credential с PRF extension...");

				// Генерируем тестовый User ID
				byte[] testUserId = new byte[32];
				using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
				{
					rng.GetBytes(testUserId);
				}

				Log($"  User ID: {BitConverter.ToString(testUserId, 0, 8).Replace("-", "")}... ({testUserId.Length} байт)");

				// Включаем логирование для диагностики
				WebAuthnHelper.Logger = (msg) => Log($"  {msg}");

				// Создаём credential
				byte[] credentialId;
				byte[] creationSecret;
				try
				{
					var created = WebAuthnHelper.CreateCredential(this.Handle, testUserId, "KeePass: диагностика PRF");
					credentialId = created.CredentialId;
					creationSecret = created.PrfSecret;
					Log($"✓ Credential создан успешно!");
					Log($"  Credential ID: {BitConverter.ToString(credentialId, 0, Math.Min(16, credentialId.Length)).Replace("-", "")}... ({credentialId.Length} байт)");
					if (creationSecret != null)
						Log($"  PRF secret при создании: {BitConverter.ToString(creationSecret, 0, Math.Min(8, creationSecret.Length)).Replace("-", " ")}... ({creationSecret.Length} байт)");
				}
				catch (WebAuthnException ex)
				{
					Log($"❌ ОШИБКА при создании credential: {ex.Message}");
					Log("----------------------------------------");
					Log("");
					WebAuthnHelper.Logger = null;
					return;
				}

				Log("");
				Log("Шаг 2: Получение PRF secret от аутентификатора...");
				Log("  (Снова потребуется PIN и подтверждение на ключе)");

				// Пауза для завершения операции
				System.Threading.Thread.Sleep(500);

				// Получаем PRF secret
				byte[] prfSecret;
				try
				{
					// Discoverable‑режим (как при разблокировке базы): allowList пуст, credential ID — из ответа
					PrfResult assertion = WebAuthnHelper.GetPrfSecret(this.Handle);
					prfSecret = assertion.PrfSecret;
					Log(System.Linq.Enumerable.SequenceEqual(assertion.CredentialId, credentialId)
						? "  ✓ Аутентификатор предъявил только что созданный credential"
						: "  ⚠ Предъявлен другой credential (выбран не тот аккаунт?) — секрет сравнивать нельзя");
					
					if (prfSecret != null && prfSecret.Length > 0)
					{
						Log($"✓✓✓ УСПЕХ! PRF secret получен!");
						Log($"  Длина: {prfSecret.Length} байт");
						Log($"  Первые байты: {BitConverter.ToString(prfSecret, 0, Math.Min(8, prfSecret.Length)).Replace("-", " ")}");
						if (creationSecret != null)
						{
							bool same = creationSecret.Length == prfSecret.Length
								&& System.Linq.Enumerable.SequenceEqual(creationSecret, prfSecret);
							Log(same
								? "  ✓ Секрет совпадает с полученным при создании (PRF детерминирован)"
								: "  ❌ Секрет НЕ совпадает с полученным при создании — ключ будет ненадёжен!");
							Array.Clear(creationSecret, 0, creationSecret.Length);
						}
						Log("");
						Log("╔════════════════════════════════════════════════════════════╗");
						Log("║  ✓ ВАШ КЛЮЧ ПОДДЕРЖИВАЕТ PRF!                             ║");
						Log("║  ✓ Можно использовать для KeePass мастер-ключа           ║");
						Log("╚════════════════════════════════════════════════════════════╝");
						
						// Очищаем секрет из памяти
						Array.Clear(prfSecret, 0, prfSecret.Length);
					}
					else
					{
						Log($"❌ PRF secret получен, но пустой!");
						Log("  Ваш ключ может не поддерживать PRF.");
					}
				}
				catch (WebAuthnException ex)
				{
					Log($"❌ ОШИБКА при получении PRF secret: {ex.Message}");
					Log("");
					Log("╔════════════════════════════════════════════════════════════╗");
					Log("║  ❌ ВАШ КЛЮЧ НЕ ПОДДЕРЖИВАЕТ PRF                          ║");
					Log("║     или Windows WebAuthn API не передал расширение        ║");
					Log("╚════════════════════════════════════════════════════════════╝");
					Log("");
					Log("Возможные причины:");
					Log("  1. Ключ не поддерживает расширение PRF (WebAuthn Level 3)");
					Log("  2. Credential не был создан с PRF (ошибка в коде)");
					Log("  3. Проблемы с Windows WebAuthn API");
					Log("");
					Log("Рекомендации:");
					Log("  - Используйте современный FIDO2 ключ (YubiKey 5, Google Titan и др.)");
					Log("  - Обновите прошивку вашего ключа");
					Log("  - Проверьте обновления Windows 11");
					Log("  - Убедитесь, что используется Windows 11 или Windows 10 22H2+");
				}

				// Отключаем логирование
				WebAuthnHelper.Logger = null;

				Log("");
				Log("Тест завершён.");
				Log("----------------------------------------");
				Log("");
			}
			catch (Exception ex)
			{
				Log($"❌ НЕПРЕДВИДЕННАЯ ОШИБКА: {ex.Message}");
				Log($"   Тип: {ex.GetType().Name}");
				Log($"   Stack Trace: {ex.StackTrace}");
				Log("----------------------------------------");
				Log("");
				WebAuthnHelper.Logger = null;
			}
		}

		private void BtnClose_Click(object sender, EventArgs e)
		{
			this.Close();
		}

		private void Log(string message)
		{
			logBuilder.AppendLine(message);
			txtLog.Text = logBuilder.ToString();
			txtLog.SelectionStart = txtLog.Text.Length;
			txtLog.ScrollToCaret();
			Application.DoEvents(); // Обновляем UI
		}
	}
}

