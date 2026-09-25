using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// KeePassPasskeyKeyProvider plugin form: WebAuthn API info, Windows Hello credential cleanup
	/// and PRF diagnostics. Database devices are on the "FIDO2" tab in "File → Database Settings".
	/// </summary>
	public partial class FIDO2OptionsForm : Form
	{
		private readonly IPluginHost host;
		private List<HelloCredentialInfo> credentials = new List<HelloCredentialInfo>();

		public FIDO2OptionsForm(IPluginHost pluginHost)
		{
			InitializeComponent();
			host = pluginHost;
			groupBoxHello.Text = string.Format(Strings.HelloCredentialsGroup, WebAuthnHelper.RpId);

			if (!WebAuthnHelper.IsWebAuthnAvailable())
			{
				ShowError(Strings.WebAuthnUnavailableRequires);
				checkedListCredentials.Enabled = false;
				buttonDeleteChecked.Enabled = false;
				buttonRefresh.Enabled = false;
				return;
			}

			uint apiVersion = WebAuthnHelper.GetApiVersion();
			ShowInfo(string.Format(Strings.WebAuthnAvailableInfo, apiVersion));
			RefreshCredentials();
		}

		/// <summary>
		/// Re-reads Hello credentials. Used ones are not shown, nothing is checked in advance:
		/// a moved or renamed database is not detected, so every deletion is the user's decision
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
				labelHelloStatus.Text = string.Format(Strings.GetListFailed, ex.Message);
				return;
			}

			foreach (HelloCredentialInfo info in credentials)
			{
				string path = info.DatabasePath ?? info.Credential.UserName;
				checkedListCredentials.Items.Add($"{path} — {info.StatusText}", false);
			}

			labelHelloStatus.Text = credentials.Count == 0
				? Strings.NoUnusedCredentials
				: Strings.UnusedCredentialsHint;
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

			var result = MessageBox.Show(this,
				string.Format(Strings.DeleteCredentialsConfirm, toDelete.Count) + "\n\n" +
				Strings.DeleteCredentialsRisk + "\n\n" +
				Strings.ActionIrreversible,
				Strings.DeleteCredentialsTitle, MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
			if (result != DialogResult.Yes) return;

			DeleteInBackground(toDelete);
		}

		/// <summary>
		/// WebAuthNDeletePlatformCredential blocks the thread for tens of seconds — delete in the background,
		/// showing progress; the UI is blocked meanwhile.
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
					MessageBox.Show(this, string.Format(Strings.DeletedCount, t.Result, toDelete.Count), "KeePassPasskeyKeyProvider",
					                MessageBoxButtons.OK, MessageBoxIcon.Warning);
				RefreshCredentials();
			}, TaskScheduler.FromCurrentSynchronizationContext());
		}

		private void ReportProgress(int current, int total)
		{
			progressBar.Value = current - 1;
			labelHelloStatus.Text = string.Format(Strings.DeletingCredential, current, total);
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
			// The event fires before the state changes (also from Items.Add before the handle exists) — account for NewValue
			int count = checkedListCredentials.CheckedItems.Count
				+ (e.NewValue == CheckState.Checked ? 1 : 0)
				- (e.CurrentValue == CheckState.Checked ? 1 : 0);
			buttonDeleteChecked.Enabled = count > 0;
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
		/// Diagnostics button handler
		/// </summary>
		private void DiagnosticsButtonClick(object sender, EventArgs e)
		{
			using (var diagnosticsForm = new FIDO2DiagnosticsForm())
				diagnosticsForm.ShowDialog(this);
		}
	}
}
