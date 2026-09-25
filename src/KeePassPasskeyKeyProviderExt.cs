using System;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassLib;

namespace KeePassPasskeyKeyProvider
{
	public class KeePassPasskeyKeyProviderExt : Plugin
	{
		public IPluginHost PluginHost;
		private FIDO2KeyProvider keyProvider;

		public override bool Initialize(IPluginHost host)
		{
			if (host == null)
			{
				return false;
			}

			PluginHost = host;
			keyProvider = new FIDO2KeyProvider(host);
			PluginHost.KeyProviderPool.Add(keyProvider);
			PluginHost.MainWindow.FileCreated += OnFileCreated;
			PluginHost.MainWindow.FileOpened += OnFileOpened;
			PluginHost.MainWindow.FileSaving += OnFileSaving;
			PluginHost.MainWindow.MasterKeyChanged += OnMasterKeyChanged;
			GlobalWindowManager.WindowAdded += OnWindowAdded;
			return true;
		}

		private static void OnFileOpened(object sender, FileOpenedEventArgs e)
		{
			DeviceKeyStore.Remember(e?.Database);
		}

		/// <summary>Merging another database (import, synchronization) must not replace the device records</summary>
		private static void OnFileSaving(object sender, FileSavingEventArgs e)
		{
			DeviceKeyStore.RestoreIfChanged(e?.Database);
		}

		/// <summary>
		/// New database with our key: the device was already written when database settings were shown (otherwise now).
		/// KeePass does not save a new database itself, and without a file with records it cannot be opened, so we save it.
		/// </summary>
		private void OnFileCreated(object sender, FileCreatedEventArgs e)
		{
			PwDatabase db = e?.Database;
			if (db == null || !FIDO2KeyProvider.UsesFido2Key(db)) return;

			FIDO2KeyProvider.RegisterPendingDevice(db);
			PluginHost.MainWindow.SaveDatabase(db, null);
		}

		/// <summary>
		/// Master key change. If the user chose to keep devices, their wrapped keys are re-wrapped
		/// for the new key. Otherwise (or if the new master key has no FIDO2) the records wrap an invalid key, so we remove them.
		/// </summary>
		private void OnMasterKeyChanged(object sender, MasterKeyChangedEventArgs e)
		{
			PwDatabase db = e?.Database;
			if (db == null) return;

			// Windows Hello credentials are not deleted: they may be needed for old copies of the database
			if (!FIDO2KeyProvider.PendingKeepsDevices(db))
				DeviceKeyStore.Clear(db);

			if (FIDO2KeyProvider.RegisterPendingDevice(db))
				PluginHost.MainWindow.SaveDatabase(db, null);
		}

		/// <summary>
		/// Adds the "FIDO2" tab to the database settings dialog (new and existing).
		/// The master key is already set by now (KeyCreationForm comes first), so for a new database
		/// the device it was created with is written here, before "OK", so it appears in the list right away.
		/// </summary>
		private void OnWindowAdded(object sender, GwmWindowEventArgs e)
		{
			var settingsForm = e.Form as DatabaseSettingsForm;
			if (settingsForm == null) return;

			TabControl tabs = FindTabControl(settingsForm);
			if (tabs == null) return;

			var control = new FIDO2DevicesControl { Dock = DockStyle.Fill };
			var page = new TabPage("FIDO2");
			page.Controls.Add(control);
			tabs.TabPages.Add(page);

			// The database is available after InitEx; by Shown it is already assigned
			settingsForm.Shown += (s, args) =>
			{
				PwDatabase db = settingsForm.DatabaseEx;
				// The device of a just-created master key was written, so this is a new FIDO2 database:
				// show the tab right away so the other devices can be added
				if (FIDO2KeyProvider.RegisterPendingDevice(db))
					tabs.SelectedTab = page;
				control.Initialize(PluginHost, db);
			};
		}

		private static TabControl FindTabControl(Control parent)
		{
			foreach (Control c in parent.Controls)
			{
				if (c is TabControl tabs) return tabs;
				TabControl nested = FindTabControl(c);
				if (nested != null) return nested;
			}
			return null;
		}

		private void OnMenuItemClick(object sender, EventArgs e)
		{
			var form = new FIDO2OptionsForm(PluginHost);
			UIUtil.ShowDialogAndDestroy(form);
		}

		public override void Terminate()
		{
			GlobalWindowManager.WindowAdded -= OnWindowAdded;
			PluginHost.MainWindow.MasterKeyChanged -= OnMasterKeyChanged;
			PluginHost.MainWindow.FileSaving -= OnFileSaving;
			PluginHost.MainWindow.FileOpened -= OnFileOpened;
			PluginHost.MainWindow.FileCreated -= OnFileCreated;
			PluginHost.KeyProviderPool.Remove(keyProvider);
		}

		public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
		{
			if (t != PluginMenuType.Main)
			{
				return null;
			}

			var menuItem = new ToolStripMenuItem("KeePassPasskeyKeyProvider", SmallIcon);
			menuItem.Click += OnMenuItemClick;

			return menuItem;
		}

		// Standard KeePass "key" icon (16×16)
		public override Image SmallIcon => PluginHost?.MainWindow.ClientIcons.Images[(int)PwIcon.Key];
		public override string UpdateUrl => "https://raw.githubusercontent.com/brlumen/KeePassPasskeyKeyProvider/master/keepass.version";
	}
}
