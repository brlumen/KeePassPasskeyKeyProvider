using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.UI;

namespace KeePassPasskeyKeyProvider.Fido2
{
	/// <summary>
	/// PIN of a security key. The PIN is typed into KeePass's protected text box (as the master password is) and leaves it
	/// only as the UTF-8 array <see cref="Ask"/> returns.
	/// </summary>
	internal sealed class PinForm : Form
	{
		private readonly SecureTextBoxEx pinBox;
		private readonly Button ok;

		private PinForm(string device, IList<string> notes, bool warning)
		{
			Text = Strings.PinTitle;
			FormBorderStyle = FormBorderStyle.FixedDialog;
			StartPosition = FormStartPosition.CenterParent;
			MinimizeBox = false;
			MaximizeBox = false;
			ShowInTaskbar = false;
			AutoSize = true;
			AutoSizeMode = AutoSizeMode.GrowAndShrink;

			var layout = new TableLayoutPanel
			{
				ColumnCount = 1,
				AutoSize = true,
				AutoSizeMode = AutoSizeMode.GrowAndShrink,
				Dock = DockStyle.Fill,
				Padding = new Padding(9)
			};
			layout.Controls.Add(new Label { Text = string.Format(Strings.SecurityKeyPin, device), AutoSize = true, MaximumSize = new Size(360, 0), Margin = new Padding(3, 3, 3, 9) });
			pinBox = new SecureTextBoxEx { Width = 360, Margin = new Padding(3, 0, 3, 6) };
			pinBox.EnableProtection(true);
			pinBox.TextChanged += (s, e) => ok.Enabled = pinBox.TextLength >= Fido2Authenticator.MinPinLength;
			layout.Controls.Add(pinBox);

			if (notes.Count > 0)
			{
				layout.Controls.Add(new Label
				{
					Text = string.Join(Environment.NewLine, notes),
					AutoSize = true,
					MaximumSize = new Size(360, 0),
					ForeColor = warning ? Color.Firebrick : SystemColors.GrayText,
					Margin = new Padding(3, 0, 3, 9)
				});
			}

			ok = new Button { Text = Strings.Continue, DialogResult = DialogResult.OK, Size = new Size(90, 25), Enabled = false };
			var cancel = new Button { Text = Strings.Cancel, DialogResult = DialogResult.Cancel, Size = new Size(90, 25) };
			var buttons = new FlowLayoutPanel
			{
				FlowDirection = FlowDirection.RightToLeft,
				AutoSize = true,
				AutoSizeMode = AutoSizeMode.GrowAndShrink,
				Dock = DockStyle.Fill,
				Margin = new Padding(0)
			};
			buttons.Controls.Add(cancel);
			buttons.Controls.Add(ok);
			layout.Controls.Add(buttons);
			Controls.Add(layout);
			AcceptButton = ok;
			CancelButton = cancel;
		}

		/// <summary>PIN in UTF-8, or null if the user cancelled; the caller zeroes the array</summary>
		/// <param name="notes">Lines under the PIN box (see <see cref="PinNotes"/>)</param>
		/// <param name="warning">The notes are a warning (red)</param>
		public static byte[] Ask(IWin32Window owner, string device, IList<string> notes, bool warning)
		{
			using (var form = new PinForm(device, notes, warning))
			{
				bool entered = form.ShowDialog(owner) == DialogResult.OK;
				byte[] pin = entered ? form.pinBox.TextEx.ReadUtf8() : null;
				form.pinBox.ResetTextEx();
				return pin;
			}
		}

		protected override void OnShown(EventArgs e)
		{
			base.OnShown(e);
			pinBox.Focus();
		}
	}
}
