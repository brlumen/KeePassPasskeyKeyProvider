using System;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider.Browser
{
	/// <summary>
	/// Modal "continue in the browser" dialog: opens <see cref="Url"/> when shown and closes with the result of
	/// <see cref="Finish"/>, with Cancel on the button and with Abort on timeout
	/// </summary>
	internal sealed class BrowserWaitForm : Form
	{
		private readonly Timer timeout;
		private readonly object sync = new object();
		private bool shown;
		private DialogResult earlyResult = DialogResult.None;

		public BrowserWaitForm(string message, int timeoutMs)
		{
			Text = "KeePassPasskeyKeyProvider";
			FormBorderStyle = FormBorderStyle.FixedDialog;
			StartPosition = FormStartPosition.CenterParent;
			MinimizeBox = false;
			MaximizeBox = false;
			ShowInTaskbar = false;
			AutoSize = true;
			AutoSizeMode = AutoSizeMode.GrowAndShrink;

			var label = new Label { Text = message, AutoSize = true, MaximumSize = new Size(420, 0), Margin = new Padding(3, 3, 3, 12) };
			var progress = new ProgressBar { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, Width = 420, Height = 14, Margin = new Padding(3, 0, 3, 12) };
			var openAgain = new LinkLabel { Text = Strings.BrowserOpenAgain, AutoSize = true, Margin = new Padding(3, 0, 3, 12) };
			openAgain.LinkClicked += (s, e) => OpenBrowser();
			var cancel = new Button { Text = Strings.Cancel, DialogResult = DialogResult.Cancel, Size = new Size(90, 25), Anchor = AnchorStyles.Right };

			var layout = new TableLayoutPanel
			{
				ColumnCount = 1,
				AutoSize = true,
				AutoSizeMode = AutoSizeMode.GrowAndShrink,
				Dock = DockStyle.Fill,
				Padding = new Padding(9)
			};
			layout.Controls.Add(label);
			layout.Controls.Add(progress);
			layout.Controls.Add(openAgain);
			layout.Controls.Add(cancel);
			Controls.Add(layout);
			CancelButton = cancel;

			timeout = new Timer { Interval = timeoutMs };
			timeout.Tick += (s, e) => DialogResult = DialogResult.Abort;
		}

		/// <summary>Page of the ceremony, opened when the dialog is shown</summary>
		public string Url { get; set; }

		/// <summary>Closes the dialog with the result; may be called from any thread, also before the dialog is shown</summary>
		public void Finish(DialogResult result)
		{
			lock (sync)
			{
				// Before the handle exists BeginInvoke fails: the result is applied when the dialog is shown
				if (!shown)
				{
					earlyResult = result;
					return;
				}
			}
			try
			{
				BeginInvoke((Action)(() => DialogResult = result));
			}
			catch (InvalidOperationException)
			{
				// the dialog is already closed
			}
		}

		protected override void OnShown(EventArgs e)
		{
			base.OnShown(e);
			DialogResult result;
			lock (sync)
			{
				shown = true;
				result = earlyResult;
			}
			if (result != DialogResult.None)
			{
				DialogResult = result; // the ceremony ended before the browser was opened
				return;
			}
			timeout.Start();
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

		protected override void Dispose(bool disposing)
		{
			if (disposing) timeout.Dispose();
			base.Dispose(disposing);
		}
	}
}
