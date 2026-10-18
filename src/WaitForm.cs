using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Modal "waiting for the authenticator" dialog: a message, a progress bar and Cancel. Another thread ends the wait
	/// with <see cref="Finish"/>, changes the message with <see cref="SetMessage"/> and runs dialogs over it with
	/// <see cref="Post"/>, also before the dialog is shown; with a timeout the dialog closes with Abort.
	/// </summary>
	internal class WaitForm : Form
	{
		private readonly Label label;
		private readonly Timer timeout;
		private readonly object sync = new object();
		private readonly List<Action> early = new List<Action>();
		private bool shown;

		/// <param name="timeoutMs">0: no timeout</param>
		/// <param name="extra">Control under the progress bar; null if none</param>
		public WaitForm(string message, int timeoutMs = 0, Control extra = null)
		{
			Text = "KeePassPasskeyKeyProvider";
			FormBorderStyle = FormBorderStyle.FixedDialog;
			StartPosition = FormStartPosition.CenterParent;
			MinimizeBox = false;
			MaximizeBox = false;
			ShowInTaskbar = false;
			AutoSize = true;
			AutoSizeMode = AutoSizeMode.GrowAndShrink;

			label = new Label { Text = message, AutoSize = true, MaximumSize = new Size(420, 0), Margin = new Padding(3, 3, 3, 12) };
			var progress = new ProgressBar { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, Width = 420, Height = 14, Margin = new Padding(3, 0, 3, 12) };
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
			if (extra != null)
				layout.Controls.Add(extra);
			layout.Controls.Add(cancel);
			Controls.Add(layout);
			CancelButton = cancel;

			if (timeoutMs > 0)
			{
				timeout = new Timer { Interval = timeoutMs };
				timeout.Tick += (s, e) => DialogResult = DialogResult.Abort;
			}
		}

		/// <summary>Closes the dialog with the result; may be called from any thread, also before the dialog is shown</summary>
		public void Finish(DialogResult result) => Post(() => DialogResult = result);

		/// <summary>Replaces the message; may be called from any thread, also before the dialog is shown</summary>
		public void SetMessage(string message) => Post(() => label.Text = message);

		/// <summary>
		/// Runs the action on the thread of the dialog once it is shown, in the order of the calls; may be called from any
		/// thread. An action posted to a closed dialog does not run.
		/// </summary>
		public void Post(Action action)
		{
			lock (sync)
			{
				// Before the dialog is shown the action would run too early or be lost (no window yet)
				if (!shown)
				{
					early.Add(action);
					return;
				}
			}
			try
			{
				BeginInvoke(action);
			}
			catch (InvalidOperationException)
			{
				// the dialog is already closed
			}
		}

		/// <summary>The dialog is shown and nothing has ended the wait yet</summary>
		protected virtual void OnWaitStarted()
		{
		}

		protected override void OnShown(EventArgs e)
		{
			base.OnShown(e);
			Action[] actions;
			lock (sync)
			{
				shown = true;
				actions = early.ToArray();
				early.Clear();
			}
			foreach (Action action in actions)
				action();
			// The wait may have ended before the dialog was shown
			if (DialogResult != DialogResult.None)
				return;
			timeout?.Start();
			OnWaitStarted();
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing) timeout?.Dispose();
			base.Dispose(disposing);
		}
	}
}
