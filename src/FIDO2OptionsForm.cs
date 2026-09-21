using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassFIDO2.WebAuthn;

namespace KeePassFIDO2
{
	/// <summary>
	/// Форма плагина KeePassFIDO2: информация о WebAuthn API, очистка credential Windows Hello
	/// и диагностика PRF. Устройства базы — вкладка «FIDO2» в «Файл → Параметры базы».
	/// </summary>
	public partial class FIDO2OptionsForm : Form
	{
		private readonly IPluginHost host;
		private List<HelloCredentialInfo> credentials = new List<HelloCredentialInfo>();

		public FIDO2OptionsForm(IPluginHost pluginHost)
		{
			InitializeComponent();
			host = pluginHost;

			if (!WebAuthnHelper.IsWebAuthnAvailable())
			{
				ShowError("Windows WebAuthn API недоступен.\n\n" +
				          "Требуется Windows 10 22H2 или Windows 11 (WebAuthn API v4+).");
				checkedListCredentials.Enabled = false;
				buttonDeleteChecked.Enabled = false;
				buttonRefresh.Enabled = false;
				return;
			}

			uint apiVersion = WebAuthnHelper.GetApiVersion();
			ShowInfo($"Windows WebAuthn API доступен (версия {apiVersion}).\n" +
			         "Credential хранится на устройстве (discoverable), файлы рядом с базой не нужны.\n" +
			         "Устройства базы: Файл → Параметры базы → вкладка «FIDO2».");

			groupBoxHello.Text = $"Credential Windows Hello для {WebAuthnHelper.RpId}";
			RefreshCredentials();
		}

		/// <summary>
		/// Перечитывает credential Hello. Используемые не показываются; безопасные к удалению (база не найдена) отмечаются сразу
		/// </summary>
		private void RefreshCredentials()
		{
			checkedListCredentials.Items.Clear();
			try
			{
				credentials = HelloCredentialAudit.Run(host)
					.FindAll(c => c.Status != HelloCredentialStatus.InUse);
			}
			catch (Exception ex)
			{
				credentials = new List<HelloCredentialInfo>();
				labelHelloStatus.Text = $"Не удалось получить список: {ex.Message}";
				return;
			}

			foreach (HelloCredentialInfo info in credentials)
			{
				string path = info.DatabasePath ?? info.Credential.UserName;
				checkedListCredentials.Items.Add($"{path} — {info.StatusText}", info.IsSafeToDelete);
			}

			labelHelloStatus.Text = credentials.Count == 0
				? "Неиспользуемых credential нет."
				: "Показаны только credential, не привязанные к существующим базам. Отмечены те, чьи файлы\n" +
				  "не найдены; остальные удаляйте осознанно — без credential базу открыть будет нельзя.";
			UpdateDeleteButton();
		}

		private void UpdateDeleteButton()
		{
			buttonDeleteChecked.Enabled = checkedListCredentials.CheckedItems.Count > 0;
		}

		private void DeleteCheckedButtonClick(object sender, EventArgs e)
		{
			var toDelete = new List<HelloCredentialInfo>();
			foreach (int index in checkedListCredentials.CheckedIndices)
				toDelete.Add(credentials[index]);
			if (toDelete.Count == 0) return;

			bool risky = toDelete.Exists(c => !c.IsSafeToDelete);
			var result = MessageBox.Show(this,
				$"Удалить {toDelete.Count} credential Windows Hello?\n\n" +
				(risky ? "Среди отмеченных есть credential, для которых нельзя подтвердить, что они не используются\n" +
				         "(база существует, но в её заголовке credential нет, либо путь к базе неизвестен).\n" +
				         "Если такой credential — единственный ключ базы, открыть её будет невозможно.\n\n" : "") +
				"Действие необратимо.",
				"Удаление credential", MessageBoxButtons.YesNo,
				risky ? MessageBoxIcon.Warning : MessageBoxIcon.Question);
			if (result != DialogResult.Yes) return;

			DeleteInBackground(toDelete);
		}

		/// <summary>
		/// WebAuthNDeletePlatformCredential блокирует поток на десятки секунд — удаляем в фоне,
		/// показывая прогресс; UI на это время блокируется.
		/// </summary>
		private void DeleteInBackground(List<HelloCredentialInfo> toDelete)
		{
			SetBusy(true, toDelete.Count);

			Task.Run(() =>
			{
				int deleted = 0;
				for (int i = 0; i < toDelete.Count; i++)
				{
					int current = i + 1;
					BeginInvoke(new Action(() => ReportProgress(current, toDelete.Count)));
					if (WebAuthnHelper.DeletePlatformCredential(toDelete[i].Credential.CredentialId)) deleted++;
				}
				return deleted;
			}).ContinueWith(t =>
			{
				SetBusy(false, 0);
				if (t.Result < toDelete.Count)
					MessageBox.Show(this, $"Удалено {t.Result} из {toDelete.Count}.", "KeePassFIDO2",
					                MessageBoxButtons.OK, MessageBoxIcon.Warning);
				RefreshCredentials();
			}, TaskScheduler.FromCurrentSynchronizationContext());
		}

		private void ReportProgress(int current, int total)
		{
			progressBar.Value = current - 1;
			labelHelloStatus.Text = $"Удаление credential {current} из {total}…";
		}

		private void SetBusy(bool busy, int total)
		{
			progressBar.Visible = busy;
			progressBar.Maximum = Math.Max(total, 1);
			progressBar.Value = 0;
			checkedListCredentials.Enabled = !busy;
			buttonDeleteChecked.Enabled = !busy;
			buttonRefresh.Enabled = !busy;
			buttonDiagnostics.Enabled = !busy;
			ControlBox = !busy;
			UseWaitCursor = busy;
		}

		private void RefreshButtonClick(object sender, EventArgs e)
		{
			RefreshCredentials();
		}

		private void CredentialsItemCheck(object sender, ItemCheckEventArgs e)
		{
			// Событие приходит до изменения состояния — пересчитываем после него
			BeginInvoke(new Action(UpdateDeleteButton));
		}

		private void ShowInfo(string message)
		{
			textBoxTop.Text = message;
			textBoxTop.ForeColor = System.Drawing.SystemColors.ControlText;
		}

		private void ShowError(string message)
		{
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
