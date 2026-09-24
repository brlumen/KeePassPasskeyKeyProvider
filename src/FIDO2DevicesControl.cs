using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskey.WebAuthn;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassPasskey
{
	/// <summary>
	/// Управление дополнительными устройствами и фразой восстановления базы (записи в PublicCustomData).
	/// Встраивается во вкладку «FIDO2» диалога параметров базы.
	/// </summary>
	public partial class FIDO2DevicesControl : UserControl
	{
		private IPluginHost host;
		private PwDatabase database;
		private List<DeviceRecord> records = new List<DeviceRecord>();
		private bool hasRecovery;

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
			hasRecovery = false;
			labelRecovery.Text = string.Empty;

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
				hasRecovery = DeviceKeyStore.LoadRecovery(database) != null;
			}
			catch (Exception ex)
			{
				ShowStatus($"Не удалось прочитать записи устройств:\n{ex.Message}");
				SetEnabled(false);
				return;
			}

			foreach (DeviceRecord r in records)
				listBoxDevices.Items.Add(string.IsNullOrEmpty(r.Label) ? "(без названия)" : r.Label);

			UpdateRecoveryStatus();
			ShowStatus("Записи хранятся в заголовке базы и сохраняются автоматически (новая база — при нажатии «OK»). " +
			           "Удаление устройства или фразы заменяет мастер‑ключ базы: удалённое не откроет её новые версии. " +
			           "Последнее устройство удалить нельзя.");
			SetEnabled(true);
		}

		/// <summary>Состояние фразы; единственное устройство без фразы — предупреждение о риске потери доступа</summary>
		private void UpdateRecoveryStatus()
		{
			buttonRecovery.Text = hasRecovery ? "Заменить фразу" : "Создать фразу восстановления";
			if (hasRecovery)
			{
				labelRecovery.ForeColor = SystemColors.ControlText;
				labelRecovery.Text = "Фраза восстановления создана: она открывает базу без устройства.";
			}
			else if (records.Count == 1)
			{
				labelRecovery.ForeColor = Color.Firebrick;
				labelRecovery.Text = "Устройство одно, фразы восстановления нет: при его потере или поломке база станет " +
				                     "недоступна. Добавьте второе устройство или создайте фразу восстановления.";
			}
			else
			{
				labelRecovery.ForeColor = SystemColors.ControlText;
				labelRecovery.Text = "Фраза восстановления не создана.";
			}
		}

		private void SetEnabled(bool enabled)
		{
			listBoxDevices.Enabled = enabled;
			textBoxDeviceName.Enabled = enabled;
			buttonAddDevice.Enabled = enabled;
			buttonRemoveDevice.Enabled = enabled && CanRemoveSelected();
			buttonRecovery.Enabled = enabled;
			buttonRemoveRecovery.Enabled = enabled && hasRecovery;
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
				MessageBox.Show(this, "Укажите название устройства.", "KeePassPasskey",
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
				MessageBox.Show(this, $"Не удалось добавить устройство:\n{ex.Message}", "KeePassPasskey",
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

			// Credential на устройстве не трогаем: он может понадобиться для старых копий базы.
			// Ненужные credential Windows Hello удаляются осознанно — кнопкой «Очистка Windows Hello».
			RunBusy("Удаление устройства и замена мастер‑ключа базы…", "Не удалось удалить устройство", () =>
			{
				records.RemoveAt(index);
				FIDO2KeyProvider.RotateDatabaseKey(database, records);
				SaveRecords();
			});
		}

		private void HelloCleanupButtonClick(object sender, EventArgs e)
		{
			UIUtil.ShowDialogAndDestroy(new FIDO2OptionsForm(host));
		}

		/// <summary>
		/// Создание (замена) фразы восстановления: запись K ⊕ R в заголовок базы. Замена = отзыв старой фразы,
		/// поэтому сначала ротация ключа: иначе старая фраза с её копией обёртки из прежних версий файла дала бы K.
		/// </summary>
		private void RecoveryButtonClick(object sender, EventArgs e)
		{
			if (hasRecovery && MessageBox.Show(this,
				    "Заменить фразу восстановления?\n\nМастер‑ключ базы будет заменён, база сохранена. " +
				    "Старая фраза не откроет эту базу и её последующие версии (копии, сделанные раньше, — откроет).",
				    "Замена фразы восстановления", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
				return;

			byte[] entropy = RecoveryPhrase.GenerateEntropy();
			try
			{
				if (UIUtil.ShowDialogAndDestroy(new RecoveryPhraseForm(RecoveryPhrase.ToWords(entropy))) != DialogResult.OK)
					return;

				RunBusy("Сохранение фразы восстановления…", "Не удалось сохранить фразу восстановления", () =>
				{
					if (hasRecovery)
					{
						DeviceKeyStore.SaveRecovery(database, null);
						FIDO2KeyProvider.RotateDatabaseKey(database, records);
					}

					byte[] key = FIDO2KeyProvider.GetDatabaseKey(database);
					byte[] secret = RecoveryPhrase.DeriveSecret(entropy);
					try
					{
						DeviceKeyStore.SaveRecovery(database, DeviceKeyStore.Wrap(key, secret));
					}
					finally
					{
						MemUtil.ZeroByteArray(key);
						MemUtil.ZeroByteArray(secret);
					}
					SaveRecords();
				});
			}
			finally
			{
				MemUtil.ZeroByteArray(entropy);
			}
		}

		/// <summary>Удаление фразы = ротация ключа (как удаление устройства)</summary>
		private void RemoveRecoveryButtonClick(object sender, EventArgs e)
		{
			if (!hasRecovery) return;

			if (MessageBox.Show(this,
				    "Удалить фразу восстановления?\n\nМастер‑ключ базы будет заменён, база сохранена. " +
				    "Фраза не откроет эту базу и её последующие версии; копии, сделанные раньше, — откроет.",
				    "Удаление фразы восстановления", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
				return;

			RunBusy("Удаление фразы и замена мастер‑ключа базы…", "Не удалось удалить фразу восстановления", () =>
			{
				DeviceKeyStore.SaveRecovery(database, null);
				FIDO2KeyProvider.RotateDatabaseKey(database, records);
				SaveRecords();
			});
		}

		/// <summary>
		/// Выполняет действие под индикатором: сохранение базы (KDF) занимает секунды и блокирует UI‑поток. При ошибке — сообщение и перечитывание записей из базы.
		/// </summary>
		private void RunBusy(string busyText, string errorText, Action action)
		{
			Exception error = null;
			using (BusyIndicator.Show(this, busyText))
			{
				try
				{
					action();
				}
				catch (Exception ex)
				{
					error = ex;
				}
			}

			if (error != null)
			{
				MessageBox.Show(this, $"{errorText}:\n{error.Message}", "KeePassPasskey",
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
				UpdateDeviceList();
			}
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
