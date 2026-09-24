using System;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassLib;

namespace KeePassPasskey
{
	public class KeePassPasskeyExt : Plugin
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
			PluginHost.MainWindow.MasterKeyChanged += OnMasterKeyChanged;
			GlobalWindowManager.WindowAdded += OnWindowAdded;
			return true;
		}

		/// <summary>
		/// Новая база с нашим ключом: устройство уже записано при показе параметров базы (иначе — сейчас).
		/// KeePass новую базу сам не сохраняет, а без файла с записями её нельзя открыть — сохраняем.
		/// </summary>
		private void OnFileCreated(object sender, FileCreatedEventArgs e)
		{
			PwDatabase db = e?.Database;
			if (db == null || !FIDO2KeyProvider.UsesFido2Key(db)) return;

			FIDO2KeyProvider.RegisterPendingDevice(db);
			PluginHost.MainWindow.SaveDatabase(db, null);
		}

		/// <summary>
		/// Смена мастер‑ключа. Если пользователь выбрал сохранить устройства — их обёртки перешифровываются
		/// на новый ключ. Иначе (или новый мастер‑ключ без FIDO2) записи шифруют недействительный ключ — удаляем их.
		/// </summary>
		private void OnMasterKeyChanged(object sender, MasterKeyChangedEventArgs e)
		{
			PwDatabase db = e?.Database;
			if (db == null) return;

			// Credential Windows Hello не удаляем: они могут понадобиться для старых копий базы
			if (!FIDO2KeyProvider.PendingKeepsDevices(db))
				DeviceKeyStore.Clear(db);

			if (FIDO2KeyProvider.RegisterPendingDevice(db))
				PluginHost.MainWindow.SaveDatabase(db, null);
		}

		/// <summary>
		/// Добавляет вкладку «FIDO2» в диалог параметров базы (новой и существующей).
		/// Мастер‑ключ к этому моменту уже задан (KeyCreationForm идёт раньше), поэтому для новой базы
		/// устройство, которым он создан, записывается здесь — до «OK», чтобы сразу быть в списке.
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

			// База доступна после InitEx — к моменту Shown она уже присвоена
			settingsForm.Shown += (s, args) =>
			{
				PwDatabase db = settingsForm.DatabaseEx;
				// Записано устройство только что созданного мастер‑ключа — это новая база с FIDO2:
				// сразу показываем вкладку, чтобы можно было добавить остальные устройства
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
			PluginHost.MainWindow.FileCreated -= OnFileCreated;
			PluginHost.KeyProviderPool.Remove(keyProvider);
		}

		public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
		{
			if (t != PluginMenuType.Main)
			{
				return null;
			}

			var menuItem = new ToolStripMenuItem("KeePassPasskey", SmallIcon);
			menuItem.Click += OnMenuItemClick;

			return menuItem;
		}

		// Стандартная иконка «ключ» KeePass (16×16)
		public override Image SmallIcon => PluginHost?.MainWindow.ClientIcons.Images[(int)PwIcon.Key];
		public override string UpdateUrl => "https://raw.githubusercontent.com/brlumen/KeePassPasskey/master/KeePassPlugin/keepass.version";
	}
}
