using System;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider.Browser
{
	/// <summary>
	/// "Continue in the browser" dialog: opens <see cref="Url"/> when shown, shows the confirmation code to enter on the
	/// page (<see cref="ShowCode"/>) and closes with the result of <see cref="WaitForm.Finish"/>, with Cancel on the
	/// button and with Abort on timeout
	/// </summary>
	internal sealed class BrowserWaitForm : WaitForm
	{
		private readonly Label codeCaption;
		private readonly Label codeLabel;

		public BrowserWaitForm(string message, int timeoutMs)
			: this(message, timeoutMs, new TableLayoutPanel { ColumnCount = 1, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0) })
		{
		}

		private BrowserWaitForm(string message, int timeoutMs, TableLayoutPanel extra)
			: base(message, timeoutMs, extra)
		{
			codeCaption = new Label { Text = Strings.BrowserCodeCaption, AutoSize = true, MaximumSize = new Size(420, 0), Margin = new Padding(3, 0, 3, 3), Visible = false };
			codeLabel = new Label { AutoSize = true, Margin = new Padding(3, 0, 3, 12), Visible = false };
			codeLabel.Font = new Font(codeLabel.Font.FontFamily, 20F, FontStyle.Bold);
			var openAgain = new LinkLabel { Text = Strings.BrowserOpenAgain, AutoSize = true, Margin = new Padding(3, 0, 3, 12) };
			openAgain.LinkClicked += (s, e) => OpenBrowser();
			extra.Controls.Add(codeCaption);
			extra.Controls.Add(codeLabel);
			extra.Controls.Add(openAgain);
		}

		/// <summary>Page of the ceremony, opened when the dialog is shown</summary>
		public string Url { get; set; }

		/// <summary>Shows the confirmation code (6 digits, grouped by three); null: none</summary>
		public void ShowCode(string code)
		{
			codeLabel.Text = code == null ? string.Empty : code.Substring(0, 3) + " " + code.Substring(3);
			codeCaption.Visible = code != null;
			codeLabel.Visible = code != null;
		}

		protected override void OnWaitStarted()
		{
			OpenBrowser();
		}

		private void OpenBrowser()
		{
			try
			{
				BrowserWebAuthn.OpenUrl(Url);
			}
			catch (Exception ex)
			{
				MessageBox.Show(this, string.Format(Strings.BrowserOpenFailed, ex.Message, Url), Text,
				                MessageBoxButtons.OK, MessageBoxIcon.Warning);
			}
		}
	}
}
