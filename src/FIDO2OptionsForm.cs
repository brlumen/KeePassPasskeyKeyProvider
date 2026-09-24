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

			if (!WebAuthnHelper.IsWebAuthnAvailable())
			{
				ShowError("Windows WebAuthn API is not available.\n\n" +
				          "Requires Windows 10 22H2 or Windows 11 (WebAuthn API v4+).");
				checkedListCredentials.Enabled = false;
				buttonDeleteChecked.Enabled = false;
				buttonRefresh.Enabled = false;
				return;
			}

			uint apiVersion = WebAuthnHelper.GetApiVersion();
			ShowInfo($"Windows WebAuthn API is available (version {apiVersion}).\n" +
			         "The credential is stored on the device (discoverable); no files next to the database are needed.\n" +
			         "Database devices: File → Database Settings → \"FIDO2\" tab.");

			groupBoxHello.Text = $"Windows Hello credentials for {WebAuthnHelper.RpId}";
			RefreshCredentials();
		}

		/// <summary>
		/// Re-reads Hello credentials. Used ones are not shown; ones safe to delete (database not found) are checked right away
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
				labelHelloStatus.Text = $"Failed to get the list: {ex.Message}";
				return;
			}

			foreach (HelloCredentialInfo info in credentials)
			{
				string path = info.DatabasePath ?? info.Credential.UserName;
				checkedListCredentials.Items.Add($"{path} — {info.StatusText}", info.IsSafeToDelete);
			}

			labelHelloStatus.Text = credentials.Count == 0
				? "No unused credentials."
				: "Only credentials not linked to existing databases are shown. Checked: those whose files\n" +
				  "were not found; delete others deliberately — without its credential a database can't be opened.";
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
				$"Delete {toDelete.Count} Windows Hello credential(s)?\n\n" +
				(risky ? "Some of the checked credentials cannot be confirmed as unused\n" +
				         "(the database exists but its header does not contain the credential, or the database path is unknown).\n" +
				         "If such a credential is the only key of a database, that database cannot be opened.\n\n" : "") +
				"This action cannot be undone.",
				"Delete credentials", MessageBoxButtons.YesNo,
				risky ? MessageBoxIcon.Warning : MessageBoxIcon.Question);
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
					MessageBox.Show(this, $"Deleted {t.Result} of {toDelete.Count}.", "KeePassPasskeyKeyProvider",
					                MessageBoxButtons.OK, MessageBoxIcon.Warning);
				RefreshCredentials();
			}, TaskScheduler.FromCurrentSynchronizationContext());
		}

		private void ReportProgress(int current, int total)
		{
			progressBar.Value = current - 1;
			labelHelloStatus.Text = $"Deleting credential {current} of {total}…";
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
			// The event fires before the state changes — recalculate after it
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
		/// Diagnostics button handler
		/// </summary>
		private void DiagnosticsButtonClick(object sender, EventArgs e)
		{
			var diagnosticsForm = new FIDO2DiagnosticsForm();
			diagnosticsForm.ShowDialog(this);
		}
	}
}
