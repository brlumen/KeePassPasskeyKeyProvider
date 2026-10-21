using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePass;
using KeePass.App;
using KeePass.Plugins;
using KeePass.UI;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// After a database was opened with a classic device, offers to make that device portable (see
	/// <see cref="DeviceMigration"/>). Asked each time until the device is portable; "Don't ask again" is remembered
	/// per database (by its verification key, which its copies share).
	/// </summary>
	internal static class PortableReminder
	{
		private const string ConfigPrefix = "KeePassPasskeyKeyProvider.NoPortableReminder.";

		private static string expectedPath;
		private static byte[] expectedCredentialId;

		/// <summary>A classic device has unlocked the database (the database is not open yet)</summary>
		public static void Expect(IOConnectionInfo ioc, byte[] credentialId)
		{
			expectedPath = ioc?.Path;
			expectedCredentialId = credentialId;
		}

		/// <summary>A database has been opened: if a classic device unlocked it, the offer follows once KeePass shows it</summary>
		public static void OnOpened(IPluginHost host, PwDatabase db)
		{
			string path = expectedPath;
			byte[] credentialId = expectedCredentialId;
			expectedPath = null;
			expectedCredentialId = null;
			if (db == null || credentialId == null || !string.Equals(path, db.IOConnectionInfo.Path, StringComparison.OrdinalIgnoreCase))
				return;

			// The offer must not hold up opening; a main window without a handle yet (opening at startup) skips it
			if (host.MainWindow.IsHandleCreated)
				host.MainWindow.BeginInvoke(new Action(() => Offer(host, db, credentialId)));
		}

		/// <summary>Whether to offer making the device portable</summary>
		/// <param name="device">Device that opened the database; null if it is no longer in the records</param>
		/// <param name="canMigrate">A portable passkey can be created and the database saved here</param>
		internal static bool ShouldOffer(DeviceRecord device, bool canMigrate, bool turnedOff)
		{
			return device != null && device.Kind == DeviceKind.Classic && canMigrate && !turnedOff;
		}

		/// <summary>Identifier of the database for remembering the answer: a hash of its verification key</summary>
		internal static string DatabaseId(byte[] verificationKey)
		{
			using (var sha = SHA256.Create())
				return MemUtil.ByteArrayToHexString(sha.ComputeHash(verificationKey)).Substring(0, 32);
		}

		private static void Offer(IPluginHost host, PwDatabase db, byte[] credentialId)
		{
			// Not over another KeePass dialog (e.g. a master key change required after opening): next time instead
			PwDocument document = host.MainWindow.DocumentManager.FindDocument(db);
			if (document == null || !db.IsOpen || host.MainWindow.IsFileLocked(document) || host.MainWindow.UIIsInteractionBlocked() ||
			    GlobalWindowManager.WindowCount > 0)
				return;

			DeviceRecordSet set;
			try
			{
				set = DeviceKeyStore.LoadAll(db);
			}
			catch (InvalidDataException)
			{
				return;
			}
			if (set.VerificationKey == null)
				return;

			DeviceRecord device = DeviceKeyStore.Find(set.Devices, credentialId);
			string configKey = ConfigPrefix + DatabaseId(set.VerificationKey);
			bool canMigrate = FIDO2KeyProvider.CanUse(DeviceKind.Portable) && CanSave(db);
			if (!ShouldOffer(device, canMigrate, Program.Config.CustomConfig.GetBool(configKey, false)))
				return;

			Form owner = host.MainWindow;
			string label = string.IsNullOrEmpty(device.Label) ? Strings.Unnamed : device.Label;
			// The offer also carries the v5 warning, so the migration does not ask it again
			string message = string.Format(Strings.PortableReminder, label);
			if (!DeviceKeyStore.UsesVersion5(set))
				message += "\n" + Strings.MakePortableVersionWarning;
			message += "\n\n" + DeviceMigration.SameDevice;
			switch (UIUtil.ShowDialogAndDestroy(new ReminderForm(message)))
			{
				case DialogResult.OK:
					DeviceMigration.Run(owner, db, new[] { credentialId }, false,
						() => KeePassPasskeyKeyProviderExt.SaveDatabase(host, db));
					break;
				case DialogResult.Ignore:
					Program.Config.CustomConfig.SetBool(configKey, true);
					break;
			}
		}

		/// <summary>KeePass may save the database: allowed by the policy, and a local file is not read-only</summary>
		private static bool CanSave(PwDatabase db)
		{
			if (!AppPolicy.Current.SaveFile)
				return false;
			IOConnectionInfo ioc = db.IOConnectionInfo;
			try
			{
				return !ioc.IsLocalFile() || !File.Exists(ioc.Path) || (File.GetAttributes(ioc.Path) & FileAttributes.ReadOnly) == 0;
			}
			catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
			{
				return false;
			}
		}

		/// <summary>The offer: OK makes the device portable, Cancel asks again next time, Ignore never asks for this database</summary>
		private sealed class ReminderForm : Form
		{
			public ReminderForm(string message)
			{
				Text = "KeePassPasskeyKeyProvider";
				FormBorderStyle = FormBorderStyle.FixedDialog;
				StartPosition = FormStartPosition.CenterParent;
				MinimizeBox = false;
				MaximizeBox = false;
				ShowInTaskbar = false;
				AutoSize = true;
				AutoSizeMode = AutoSizeMode.GrowAndShrink;

				var label = new Label { Text = message, AutoSize = true, MaximumSize = new Size(440, 0), Margin = new Padding(3, 3, 3, 12) };
				var makePortable = new Button { Text = Strings.MakePortable, DialogResult = DialogResult.OK, AutoSize = true, Padding = new Padding(8, 0, 8, 0) };
				var later = new Button { Text = Strings.Later, DialogResult = DialogResult.Cancel, AutoSize = true, Padding = new Padding(8, 0, 8, 0) };
				var never = new Button { Text = Strings.DontAskAgain, DialogResult = DialogResult.Ignore, AutoSize = true, Padding = new Padding(8, 0, 8, 0) };

				var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Anchor = AnchorStyles.Right, Margin = new Padding(0) };
				buttons.Controls.Add(never);
				buttons.Controls.Add(later);
				buttons.Controls.Add(makePortable);

				var layout = new TableLayoutPanel
				{
					ColumnCount = 1,
					AutoSize = true,
					AutoSizeMode = AutoSizeMode.GrowAndShrink,
					Dock = DockStyle.Fill,
					Padding = new Padding(9)
				};
				layout.Controls.Add(label);
				layout.Controls.Add(buttons);
				Controls.Add(layout);
				AcceptButton = makePortable;
				CancelButton = later;
			}
		}
	}
}
