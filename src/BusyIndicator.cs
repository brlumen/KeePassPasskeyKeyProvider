using System;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;

namespace KeePassPasskey
{
	/// <summary>
	/// Модальная плашка «идёт операция» со спиннером поверх окна‑владельца.
	/// Работает в собственном UI‑потоке: операции KeePass (сохранение базы с KDF) обязаны
	/// выполняться в главном потоке и блокируют его, а плашка при этом продолжает анимироваться.
	/// Использование: <c>using (BusyIndicator.Show(owner, "…")) { долгая операция }</c>.
	/// </summary>
	public sealed class BusyIndicator : IDisposable
	{
		private readonly Thread thread;
		private readonly ManualResetEvent shown = new ManualResetEvent(false);
		private volatile Form form;
		private volatile bool closing;

		private BusyIndicator(Rectangle ownerBounds, string message)
		{
			thread = new Thread(() => RunForm(ownerBounds, message)) { IsBackground = true, Name = "KeePassPasskey busy" };
			thread.SetApartmentState(ApartmentState.STA);
			thread.Start();
			shown.WaitOne(2000); // не ждём вечно, если окно не удалось показать
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
				Text = "KeePassPasskey"
			};
			form.Controls.Add(layout);
			form.Load += (s, e) => form.Location = new Point(
				ownerBounds.Left + (ownerBounds.Width - form.Width) / 2,
				ownerBounds.Top + (ownerBounds.Height - form.Height) / 2);
			form.Shown += (s, e) =>
			{
				shown.Set();
				if (closing) form.Close(); // операция завершилась раньше, чем окно появилось
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
				catch (InvalidOperationException) { /* окно уже закрыто */ }
			}
			if (thread.Join(2000))
				shown.Dispose();
		}
	}
}
