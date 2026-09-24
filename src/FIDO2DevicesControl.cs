using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Manages additional devices and the database recovery phrase (records in PublicCustomData).
	/// Embedded in the "FIDO2" tab of the database settings dialog.
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
				ShowStatus(Strings.WebAuthnUnavailableShort);
				SetEnabled(false);
				return;
			}

			byte[] key = FIDO2KeyProvider.GetDatabaseKey(database);
			if (key == null)
			{
				ShowStatus(string.Format(Strings.MasterKeyNotFido2Hint, FIDO2KeyProvider.ProviderName));
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
				ShowStatus(string.Format(Strings.ReadDeviceRecordsFailed, ex.Message));
				SetEnabled(false);
				return;
			}

			foreach (DeviceRecord r in records)
				listBoxDevices.Items.Add(string.IsNullOrEmpty(r.Label) ? Strings.Unnamed : r.Label);

			UpdateRecoveryStatus();
			ShowStatus(Strings.DevicesTabInfo);
			SetEnabled(true);
		}

		/// <summary>Phrase status; a single device without a phrase shows a warning about the risk of losing access</summary>
		private void UpdateRecoveryStatus()
		{
			buttonRecovery.Text = hasRecovery ? Strings.ReplacePhrase : Strings.CreateRecoveryPhrase;
			if (hasRecovery)
			{
				labelRecovery.ForeColor = SystemColors.ControlText;
				labelRecovery.Text = Strings.RecoveryPhraseCreated;
			}
			else if (records.Count == 1)
			{
				labelRecovery.ForeColor = Color.Firebrick;
				labelRecovery.Text = Strings.SingleDeviceWarning;
			}
			else
			{
				labelRecovery.ForeColor = SystemColors.ControlText;
				labelRecovery.Text = Strings.NoRecoveryPhrase;
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

		/// <summary>Any device except the last one can be removed: without records the database cannot be opened</summary>
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
		/// Adding a device: new credential with PRF → record K ⊕ PRF in the database header
		/// </summary>
		private void AddDeviceButtonClick(object sender, EventArgs e)
		{
			string label = textBoxDeviceName.Text.Trim();
			if (label.Length == 0)
			{
				MessageBox.Show(this, Strings.EnterDeviceName, "KeePassPasskeyKeyProvider",
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
				MessageBox.Show(this, string.Format(Strings.AddDeviceFailed, ex.Message), "KeePassPasskeyKeyProvider",
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			finally
			{
				MemUtil.ZeroByteArray(key);
			}
		}

		/// <summary>
		/// Removing a device = database key rotation: otherwise the removed device would open
		/// the current file with its wrapped key K ⊕ PRF left in its copies
		/// </summary>
		private void RemoveDeviceButtonClick(object sender, EventArgs e)
		{
			if (!CanRemoveSelected()) return;
			int index = listBoxDevices.SelectedIndex;

			var result = MessageBox.Show(this,
				string.Format(Strings.RemoveDeviceConfirm, listBoxDevices.Items[index]),
				Strings.RemoveDeviceTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
			if (result != DialogResult.Yes) return;

			// The credential on the device is left untouched: it may be needed for old copies of the database.
			// Unneeded Windows Hello credentials are removed deliberately — with the "Windows Hello cleanup" button.
			RunBusy(Strings.RemovingDevice, Strings.RemoveDeviceFailed, () =>
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
		/// Creating (replacing) the recovery phrase: record K ⊕ R in the database header. Replacement = revoking the old phrase,
		/// so rotation comes first: otherwise the old phrase plus its copy of the wrapped key from earlier file versions would yield K.
		/// </summary>
		private void RecoveryButtonClick(object sender, EventArgs e)
		{
			if (hasRecovery && MessageBox.Show(this,
				    Strings.ReplacePhraseConfirm,
				    Strings.ReplacePhraseTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
				return;

			byte[] entropy = RecoveryPhrase.GenerateEntropy();
			try
			{
				if (UIUtil.ShowDialogAndDestroy(new RecoveryPhraseForm(RecoveryPhrase.ToWords(entropy))) != DialogResult.OK)
					return;

				RunBusy(Strings.SavingPhrase, Strings.SavePhraseFailed, () =>
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

		/// <summary>Removing the phrase = key rotation (same as removing a device)</summary>
		private void RemoveRecoveryButtonClick(object sender, EventArgs e)
		{
			if (!hasRecovery) return;

			if (MessageBox.Show(this,
				    Strings.RemovePhraseConfirm,
				    Strings.RemovePhraseTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
				return;

			RunBusy(Strings.RemovingPhrase, Strings.RemovePhraseFailed, () =>
			{
				DeviceKeyStore.SaveRecovery(database, null);
				FIDO2KeyProvider.RotateDatabaseKey(database, records);
				SaveRecords();
			});
		}

		/// <summary>
		/// Runs the action under a busy indicator: saving the database (KDF) takes seconds and blocks the UI thread. On error — a message and re-reading the records from the database.
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
				MessageBox.Show(this, $"{errorText}:\n{error.Message}", "KeePassPasskeyKeyProvider",
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
				UpdateDeviceList();
			}
		}

		/// <summary>
		/// Writes the records to the database and saves the file immediately. A new database has no file yet —
		/// KeePass saves it itself after "OK" in the settings dialog.
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
