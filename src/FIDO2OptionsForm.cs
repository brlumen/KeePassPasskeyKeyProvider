using System;
using System.Windows.Forms;
using KeePassFIDO2.WebAuthn;

namespace KeePassFIDO2
{
	/// <summary>
	/// Форма настроек плагина KeePassFIDO2
	/// Показывает информацию о WebAuthn API и состояние credential для текущей базы данных
	/// </summary>
	public partial class FIDO2OptionsForm : Form
	{
		private readonly KeePassFIDO2Ext keePassFIDO2Ext;

		public FIDO2OptionsForm(KeePassFIDO2Ext ext)
		{
			InitializeComponent();
			keePassFIDO2Ext = ext;

			// Проверяем доступность WebAuthn API
			if (!WebAuthnHelper.IsWebAuthnAvailable())
			{
				ShowError("Windows WebAuthn API недоступен.\n\n" +
				          "Требуется Windows 10 22H2 или Windows 11 (WebAuthn API v4+).");
				buttonManageCredential.Enabled = false;
				return;
			}

			uint apiVersion = WebAuthnHelper.GetApiVersion();
			ShowInfo($"Windows WebAuthn API доступен (версия {apiVersion}).\n\n" +
			         "Этот плагин использует нативный Windows WebAuthn API\n" +
			         "с PRF extension (WebAuthn Level 3) для безопасной генерации ключей.");

			UpdateCredentialStatus();
		}

		/// <summary>
		/// Обновляет информацию о credential для текущей базы данных
		/// </summary>
		private void UpdateCredentialStatus()
		{
			if (keePassFIDO2Ext.PluginHost.Database == null || 
			    !keePassFIDO2Ext.PluginHost.Database.IsOpen)
			{
				textBoxBottom.Text = "Откройте базу данных для управления FIDO2 credential.";
				textBoxBottom.Visible = true;
				buttonManageCredential.Enabled = false;
				return;
			}

			string databasePath = keePassFIDO2Ext.PluginHost.Database.IOConnectionInfo.Path;
			
			if (string.IsNullOrEmpty(databasePath))
			{
				textBoxBottom.Text = "Невозможно определить путь к базе данных.";
				textBoxBottom.Visible = true;
				buttonManageCredential.Enabled = false;
				return;
			}

			bool credentialExists = CredentialStorage.CredentialExists(databasePath);

			if (credentialExists)
			{
				textBoxBottom.Text = "FIDO2 credential для этой базы данных найден.\n" +
				                     "Используйте кнопку ниже для удаления credential.";
				textBoxBottom.ForeColor = System.Drawing.Color.Green;
				buttonManageCredential.Text = "Удалить FIDO2 Credential";
			}
			else
			{
				textBoxBottom.Text = "FIDO2 credential для этой базы данных не найден.\n" +
				                     "Используйте 'FIDO2 Key Provider' при создании/изменении мастер-ключа.";
				textBoxBottom.ForeColor = System.Drawing.SystemColors.ControlText;
				buttonManageCredential.Text = "Информация";
			}

			textBoxBottom.Visible = true;
			buttonManageCredential.Enabled = true;
		}

		/// <summary>
		/// Обработчик кнопки управления credential
		/// </summary>
		private void ManageCredentialButtonClick(object sender, EventArgs e)
		{
			if (keePassFIDO2Ext.PluginHost.Database == null || 
			    !keePassFIDO2Ext.PluginHost.Database.IsOpen)
			{
				MessageBox.Show("Откройте базу данных.", "KeePassFIDO2", 
				                MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}

			string databasePath = keePassFIDO2Ext.PluginHost.Database.IOConnectionInfo.Path;
			
			if (string.IsNullOrEmpty(databasePath))
			{
				MessageBox.Show("Невозможно определить путь к базе данных.", "KeePassFIDO2",
				                MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return;
			}

			bool credentialExists = CredentialStorage.CredentialExists(databasePath);

			if (credentialExists)
			{
				// Удаление credential
				var result = MessageBox.Show(
					"Вы уверены, что хотите удалить FIDO2 credential для этой базы данных?\n\n" +
					"После удаления вы больше не сможете открыть базу данных с помощью FIDO2,\n" +
					"если FIDO2 Key Provider является единственным способом доступа.\n\n" +
					"Убедитесь, что у вас есть другой способ доступа к базе данных!",
					"Удаление FIDO2 Credential",
					MessageBoxButtons.YesNo,
					MessageBoxIcon.Warning);

				if (result == DialogResult.Yes)
				{
					try
					{
						CredentialStorage.DeleteCredential(databasePath);
						MessageBox.Show("FIDO2 credential успешно удалён.", "KeePassFIDO2",
						                MessageBoxButtons.OK, MessageBoxIcon.Information);
						UpdateCredentialStatus();
					}
					catch (Exception ex)
					{
						MessageBox.Show($"Ошибка при удалении credential:\n{ex.Message}", "KeePassFIDO2",
						                MessageBoxButtons.OK, MessageBoxIcon.Error);
					}
				}
			}
			else
			{
				// Показываем информацию о том, как создать credential
				MessageBox.Show(
					"Для создания FIDO2 credential:\n\n" +
					"1. Создайте новую базу данных или откройте существующую\n" +
					"2. Перейдите в 'Файл' → 'Изменить мастер-ключ'\n" +
					"3. Выберите 'FIDO2 Key Provider (Windows WebAuthn)'\n" +
					"4. Следуйте инструкциям на экране\n\n" +
					"Credential ID будет автоматически сохранён в файл .fido2\n" +
					"рядом с вашей базой данных.",
					"Как создать FIDO2 Credential",
					MessageBoxButtons.OK,
					MessageBoxIcon.Information);
			}
		}

		private void ShowInfo(string message)
		{
			textBoxTop.Visible = true;
			textBoxTop.Text = message;
			textBoxTop.ForeColor = System.Drawing.SystemColors.ControlText;
		}

		private void ShowError(string message)
		{
			textBoxTop.Visible = true;
			textBoxTop.Text = message;
			textBoxTop.ForeColor = System.Drawing.Color.Red;
		}

		/// <summary>
		/// Обработчик кнопки диагностики
		/// </summary>
		private void DiagnosticsButtonClick(object sender, EventArgs e)
		{
			var diagnosticsForm = new FIDO2DiagnosticsForm();
			diagnosticsForm.ShowDialog(this);
		}
	}
}
