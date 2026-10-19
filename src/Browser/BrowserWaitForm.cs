using System;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider.Browser
{
	/// <summary>
	/// "Continue in the browser" dialog: opens <see cref="Url"/> when shown or, with a confirmation code to enter on the
	/// page (<see cref="ShowCode"/>), on a button click, so that the browser does not cover the code before the user
	/// has read it. Closes with the result of <see cref="WaitForm.Finish"/>, with Cancel on the button and with Abort
	/// on timeout.
	/// </summary>
	internal sealed class BrowserWaitForm : WaitForm
	{
		private readonly Label codeCaption;
		private readonly Label codeLabel;
		private readonly Button openPage;
		private readonly LinkLabel openAgain;
		private bool openOnClick;

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
			openPage = new Button { Text = Strings.BrowserOpenPage, AutoSize = true, Padding = new Padding(8, 0, 8, 0), Margin = new Padding(3, 0, 3, 12), Visible = false };
			openPage.Click += (s, e) => OpenPageClicked();
			openAgain = new LinkLabel { Text = Strings.BrowserOpenAgain, AutoSize = true, Margin = new Padding(3, 0, 3, 12) };
			openAgain.LinkClicked += (s, e) => OpenBrowser();
			extra.Controls.Add(codeCaption);
			extra.Controls.Add(codeLabel);
			extra.Controls.Add(openPage);
			extra.Controls.Add(openAgain);
		}

		/// <summary>Page of the ceremony, opened when the dialog is shown</summary>
		public string Url { get; set; }

		/// <summary>
		/// Shows the confirmation code (6 digits, grouped by three) and makes the page open on a button click;
		/// null: no code, the page opens when the dialog is shown
		/// </summary>
		public void ShowCode(string code)
		{
			openOnClick = code != null;
			codeLabel.Text = openOnClick ? code.Substring(0, 3) + " " + code.Substring(3) : string.Empty;
			codeCaption.Visible = openOnClick;
			codeLabel.Visible = openOnClick;
			openPage.Visible = openOnClick;
			openAgain.Visible = !openOnClick;
			AcceptButton = openOnClick ? openPage : null;
		}

		protected override void OnWaitStarted()
		{
			if (openOnClick)
				openPage.Focus();
			else
				OpenBrowser();
		}

		/// <summary>The page opens once from the button; then only from the link, as without a code</summary>
		private void OpenPageClicked()
		{
			AcceptButton = null;
			openPage.Visible = false;
			openAgain.Visible = true;
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
