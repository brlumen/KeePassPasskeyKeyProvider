using System;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Modal "operation in progress" overlay with a spinner on top of the owner window.
	/// Runs on its own UI thread: KeePass operations (saving the database with KDF) must
	/// run on the main thread and block it, while the overlay keeps animating.
	/// Usage: <c>using (BusyIndicator.Show(owner, "…")) { long operation }</c>.
	/// </summary>
	public sealed class BusyIndicator : IDisposable
	{
		private readonly Thread thread;
		private readonly ManualResetEvent shown = new ManualResetEvent(false);
		private volatile Form form;
		private volatile bool closing;

		private BusyIndicator(Rectangle ownerBounds, string message)
		{
			thread = new Thread(() => RunForm(ownerBounds, message)) { IsBackground = true, Name = "KeePassPasskeyKeyProvider busy" };
			thread.SetApartmentState(ApartmentState.STA);
			thread.Start();
			shown.WaitOne(2000); // don't wait forever if the window failed to show
		}

		public static BusyIndicator Show(Control owner, string message)
		{
			Form ownerForm = owner?.FindForm();
			Rectangle bounds = ownerForm != null ? ownerForm.Bounds : Screen.PrimaryScreen.WorkingArea;
			return new BusyIndicator(bounds, message);
		}

		private void RunForm(Rectangle ownerBounds, string message)
		{
			var label = new Label
			{
				Text = message,
				AutoSize = true,
				Margin = new Padding(0, 0, 0, 10)
			};
			var progress = new ProgressBar
			{
				Style = ProgressBarStyle.Marquee,
				MarqueeAnimationSpeed = 30,
				Width = 280,
				Height = 16,
				Margin = new Padding(0)
			};
			var layout = new FlowLayoutPanel
			{
				FlowDirection = FlowDirection.TopDown,
				AutoSize = true,
				AutoSizeMode = AutoSizeMode.GrowAndShrink,
				Padding = new Padding(20),
				Dock = DockStyle.Fill,
				BorderStyle = BorderStyle.FixedSingle
			};
			layout.Controls.Add(label);
			layout.Controls.Add(progress);

			form = new Form
			{
				FormBorderStyle = FormBorderStyle.None,
				ShowInTaskbar = false,
				TopMost = true,
				StartPosition = FormStartPosition.Manual,
				AutoSize = true,
				AutoSizeMode = AutoSizeMode.GrowAndShrink,
				BackColor = SystemColors.Window,
				Font = SystemFonts.MessageBoxFont,
				Text = "KeePassPasskeyKeyProvider"
			};
			form.Controls.Add(layout);
			form.Load += (s, e) => form.Location = new Point(
				ownerBounds.Left + (ownerBounds.Width - form.Width) / 2,
				ownerBounds.Top + (ownerBounds.Height - form.Height) / 2);
			form.Shown += (s, e) =>
			{
				shown.Set();
				if (closing) form.Close(); // the operation finished before the window appeared
			};

			Application.Run(form);
		}

		public void Dispose()
		{
			closing = true;
			Form f = form;
			if (f != null && f.IsHandleCreated)
			{
				try { f.BeginInvoke((Action)f.Close); }
				catch (InvalidOperationException) { /* window already closed */ }
			}
			if (thread.Join(2000))
				shown.Dispose();
		}
	}
}
