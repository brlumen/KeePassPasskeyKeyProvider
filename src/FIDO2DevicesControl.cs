using System;
using System.Collections.Generic;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassFIDO2.WebAuthn;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassFIDO2
{
	/// <summary>
	/// Управление дополнительными устройствами базы (записи в PublicCustomData).
	/// Встраивается во вкладку «FIDO2» диалога параметров базы.
	/// </summary>
	public partial class FIDO2DevicesControl : UserControl
	{
		private IPluginHost host;
		private PwDatabase database;
		private List<DeviceRecord> records = new List<DeviceRecord>();

		public FIDO2DevicesControl()
		{
			InitializeComponent();
		}

		public void Initialize(IPluginHost pluginHost, PwDatabase db)
		{
			host = pluginHost;
			database = db;
			UpdateDeviceList();
		}

		private void UpdateDeviceList()
		{
			listBoxDevices.Items.Clear();
			records = new List<DeviceRecord>();

			if (!WebAuthnHelper.IsWebAuthnAvailable())
			{
				ShowStatus("Windows WebAuthn API недоступен (требуется Windows 10 22H2 / Windows 11).");
				SetEnabled(false);
				return;
			}

			byte[] key = FIDO2KeyProvider.GetDatabaseKey(database);
			if (key == null)
			{
				ShowStatus("Мастер‑ключ этой базы не использует FIDO2.\n" +
				           "Файл → Изменить мастер‑ключ → «FIDO2 Key Provider (Windows WebAuthn)».");
				SetEnabled(false);
				return;
			}
			MemUtil.ZeroByteArray(key);

			try
			{
				records = DeviceKeyStore.Load(database);
			}
			catch (Exception ex)
			{
				ShowStatus($"Не удалось прочитать записи устройств:\n{ex.Message}");
				SetEnabled(false);
				return;
			}

			foreach (DeviceRecord r in records)
				listBoxDevices.Items.Add(string.IsNullOrEmpty(r.Label) ? "(без названия)" : r.Label);

			ShowStatus("Записи хранятся в заголовке базы и сохраняются автоматически\n" +
			           "(новая база — при нажатии «OK»). Удаление устройства заменяет мастер‑ключ базы:\n" +
			           "удалённое устройство не откроет её новые версии. Последнее устройство удалить нельзя.");
			SetEnabled(true);
		}

		private void SetEnabled(bool enabled)
		{
			listBoxDevices.Enabled = enabled;
			textBoxDeviceName.Enabled = enabled;
			buttonAddDevice.Enabled = enabled;
			buttonRemoveDevice.Enabled = enabled && CanRemoveSelected();
		}

		/// <summary>Удалять можно любое устройство, кроме последнего: без записей базу не открыть</summary>
		private bool CanRemoveSelected()
		{
			int index = listBoxDevices.SelectedIndex;
			return index >= 0 && index < records.Count && records.Count > 1;
		}

		private void ShowStatus(string message)
		{
			labelStatus.Text = message;
		}

		/// <summary>
		/// Добавление устройства: новый credential с PRF → запись K ⊕ PRF в заголовок базы
		/// </summary>
		private void AddDeviceButtonClick(object sender, EventArgs e)
		{
			string label = textBoxDeviceName.Text.Trim();
			if (label.Length == 0)
			{
				MessageBox.Show(this, "Укажите название устройства.", "KeePassFIDO2",
				                MessageBoxButtons.OK, MessageBoxIcon.Information);
				textBoxDeviceName.Focus();
				return;
			}

			byte[] key = FIDO2KeyProvider.GetDatabaseKey(database);
			if (key == null)
			{
				UpdateDeviceList();
				return;
			}

			try
			{
				PrfResult created = FIDO2KeyProvider.CreateCredentialForDatabase(
					FindForm()?.Handle ?? Handle, database.IOConnectionInfo.Path);
				try
				{
					records.Add(new DeviceRecord
					{
						CredentialId = created.CredentialId,
						WrappedKey = DeviceKeyStore.Wrap(key, created.PrfSecret),
						Label = label
					});
				}
				finally
				{
					MemUtil.ZeroByteArray(created.PrfSecret);
				}

				SaveRecords();
				textBoxDeviceName.Clear();
			}
			catch (Exception ex)
			{
				MessageBox.Show(this, $"Не удалось добавить устройство:\n{ex.Message}", "KeePassFIDO2",
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			finally
			{
				MemUtil.ZeroByteArray(key);
			}
		}

		/// <summary>
		/// Удаление устройства = ротация ключа базы: иначе удалённое устройство открывало бы
		/// текущий файл своей обёрткой K ⊕ PRF, оставшейся в его копиях
		/// </summary>
		private void RemoveDeviceButtonClick(object sender, EventArgs e)
		{
			if (!CanRemoveSelected()) return;
			int index = listBoxDevices.SelectedIndex;

			var result = MessageBox.Show(this,
				$"Удалить устройство «{listBoxDevices.Items[index]}»?\n\n" +
				"Мастер‑ключ базы будет заменён новым, база сохранена. Удалённое устройство не сможет " +
				"открыть эту базу и все её последующие версии; остальные устройства продолжат открывать её " +
				"без перерегистрации.\n\n" +
				"Копии базы, сделанные до удаления (резервные копии, история версий в облаке), это устройство " +
				"по‑прежнему откроет: если в базе есть секреты, которые ему не должны быть доступны, смените их.",
				"Удаление устройства", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
			if (result != DialogResult.Yes) return;

			DeviceRecord removed = records[index];
			try
			{
				records.RemoveAt(index);
				FIDO2KeyProvider.RotateDatabaseKey(database, records);
				SaveRecords();
			}
			catch (Exception ex)
			{
				MessageBox.Show(this, $"Не удалось удалить устройство:\n{ex.Message}", "KeePassFIDO2",
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
				UpdateDeviceList();
				return;
			}

			// Если credential был на Windows Hello — удаляем и его (иначе останется «сиротой»)
			WebAuthnHelper.DeletePlatformCredential(removed.CredentialId);
		}

		/// <summary>
		/// Записывает записи в базу и сразу сохраняет файл. Для новой базы файла ещё нет —
		/// её KeePass сохранит сам после «OK» в диалоге параметров.
		/// </summary>
		private void SaveRecords()
		{
			DeviceKeyStore.Save(database, records);
			host.MainWindow.UpdateUI(false, null, false, null, false, null, true);

			if (IOConnection.FileExists(database.IOConnectionInfo))
				host.MainWindow.SaveDatabase(database, null);

			UpdateDeviceList();
		}

		private void DevicesSelectedIndexChanged(object sender, EventArgs e)
		{
			buttonRemoveDevice.Enabled = CanRemoveSelected();
		}
	}
}
