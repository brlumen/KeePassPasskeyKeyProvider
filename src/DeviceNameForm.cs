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
			labelDescription.Text =
				"A new FIDO2 credential will now be created for this database.\n" +
				"Enter below the name of the device used to create the key — it distinguishes it from others " +
				"in the database device list. If left empty, the label will be made from the device type and date.\n\n" +
				"You will need to:\n" +
				"1. Have a FIDO2 key with hmac-secret/PRF support (YubiKey 5, etc.), Windows Hello or a phone\n" +
				"2. Enter the key PIN\n" +
				"3. Confirm credential creation (usually by touching the key)\n\n" +
				"The credential is stored on the device itself — no files next to the database are needed.\n" +
				"Other devices: File → Database Settings → \"FIDO2\" tab.";

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
				labelKeepDevices.Text = $"Devices {deviceList} will keep opening the database without re-registration.";
			}
			else
			{
				labelKeepDevices.ForeColor = Color.Firebrick;
				labelKeepDevices.Text = $"Devices {deviceList} will be removed from the database. " +
				                        "Only the new device will be able to open the database.";
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
