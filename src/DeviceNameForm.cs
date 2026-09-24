using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Dialog shown before creating a credential for the master key: explanation, device name and — when changing
	/// the master key of a database with devices — the choice whether to keep them
	/// </summary>
	public partial class DeviceNameForm : Form
	{
		private readonly string deviceList;
		private readonly bool changingKey;

		/// <param name="existingDevices">Labels of the devices of the database whose master key is being changed; empty for a new database</param>
		public DeviceNameForm(IList<string> existingDevices)
		{
			InitializeComponent();
			labelDescription.Text = Strings.CreateCredentialDescription;

			changingKey = existingDevices != null && existingDevices.Count > 0;
			checkBoxKeepDevices.Visible = changingKey;
			labelKeepDevices.Visible = changingKey;
			if (changingKey)
			{
				deviceList = "\"" + string.Join("\", \"", existingDevices) + "\"";
				checkBoxKeepDevices.CheckedChanged += (s, e) => UpdateKeepDevicesText();
				UpdateKeepDevicesText();
			}
		}

		/// <summary>Entered name trimmed of surrounding spaces; empty if not specified. Available after the form is closed as well</summary>
		public string DeviceName { get; private set; } = string.Empty;

		/// <summary>Keep the other database devices (re-encrypt their wrapped keys for the new key)</summary>
		public bool KeepDevices { get; private set; }

		private void UpdateKeepDevicesText()
		{
			if (checkBoxKeepDevices.Checked)
			{
				labelKeepDevices.ForeColor = SystemColors.GrayText;
				labelKeepDevices.Text = string.Format(Strings.DevicesWillBeKept, deviceList);
			}
			else
			{
				labelKeepDevices.ForeColor = Color.Firebrick;
				labelKeepDevices.Text = string.Format(Strings.DevicesWillBeRemoved, deviceList);
			}
		}

		protected override void OnFormClosing(FormClosingEventArgs e)
		{
			DeviceName = textBoxDeviceName.Text.Trim();
			KeepDevices = changingKey && checkBoxKeepDevices.Checked;
			base.OnFormClosing(e);
		}
	}
}
