using System;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider.Browser
{
	/// <summary>
	/// "Continue in the browser" dialog: opens <see cref="Url"/> when shown and closes with the result of
	/// <see cref="WaitForm.Finish"/>, with Cancel on the button and with Abort on timeout
	/// </summary>
	internal sealed class BrowserWaitForm : WaitForm
	{
		public BrowserWaitForm(string message, int timeoutMs)
			: this(message, timeoutMs, new LinkLabel { Text = Strings.BrowserOpenAgain, AutoSize = true, Margin = new Padding(3, 0, 3, 12) })
		{
		}

		private BrowserWaitForm(string message, int timeoutMs, LinkLabel openAgain)
			: base(message, timeoutMs, openAgain)
		{
			openAgain.LinkClicked += (s, e) => OpenBrowser();
		}

		/// <summary>Page of the ceremony, opened when the dialog is shown</summary>
		public string Url { get; set; }

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
