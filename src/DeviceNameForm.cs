using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Dialog shown before creating a credential for the master key: explanation, device name, the choice of the
	/// Windows dialog or the browser and — when changing the master key of a database with devices — whether to keep them
	/// </summary>
	public partial class DeviceNameForm : Form
	{
		private readonly string deviceList;
		private readonly bool changingKey;

		/// <summary>Asks for the name of a new device</summary>
		/// <param name="existingDevices">Labels of the devices of the database whose master key is being changed; empty for a new database</param>
		/// <param name="windowsWebAuthn">Windows WebAuthn API is available; otherwise only the browser can be used</param>
		public DeviceNameForm(IList<string> existingDevices, bool windowsWebAuthn)
		{
			InitializeComponent();
			checkBoxBrowser.Checked = !windowsWebAuthn;
			checkBoxBrowser.Visible = windowsWebAuthn;
			checkBoxBrowser.CheckedChanged += (s, e) => UpdateDescription();
			UpdateDescription();

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

		/// <summary>Create the passkey in the browser (<see cref="DeviceKind.Browser"/>)</summary>
		public bool UseBrowser { get; private set; }

		private void UpdateDescription()
		{
			labelDescription.Text = checkBoxBrowser.Checked ? Strings.CreateCredentialDescriptionBrowser : Strings.CreateCredentialDescription;
		}

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
			UseBrowser = checkBoxBrowser.Checked;
			base.OnFormClosing(e);
		}
	}
}
