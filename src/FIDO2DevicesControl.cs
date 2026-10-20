using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
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
		private DeviceRecordSet set = new DeviceRecordSet();
		private bool canAdd;

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

		private bool HasRecovery => set.Recovery != null;

		private void UpdateDeviceList()
		{
			listBoxDevices.Items.Clear();
			set = new DeviceRecordSet();
			labelRecovery.Text = string.Empty;
			portableButtons.Visible = false;

			byte[] key = FIDO2KeyProvider.GetDatabaseKey(database);
			if (key == null)
			{
				ShowStatus(string.Format(Strings.MasterKeyNotFido2Hint, FIDO2KeyProvider.ProviderName));
				SetEnabled(false, false);
				return;
			}
			MemUtil.ZeroByteArray(key);

			try
			{
				set = DeviceKeyStore.LoadAll(database);
				using (SigningKey signingKey = DeviceKeyStore.LoadSigningKey(database, set.VerificationKey))
				{
					if (signingKey == null)
						throw new InvalidOperationException(Strings.SigningKeyInvalid);
				}
			}
			catch (Exception ex)
			{
				set = new DeviceRecordSet();
				ShowStatus(string.Format(Strings.ReadDeviceRecordsFailed, ex.Message));
				SetEnabled(false, false);
				return;
			}

			foreach (DeviceRecord r in set.Devices)
				listBoxDevices.Items.Add(DisplayName(r));
			UpdateRecoveryStatus();

			// Only adding a device needs an authenticator; removal and the phrase work without WebAuthn.
			// Outside Windows devices are added in the browser; Windows needs its WebAuthn API.
			canAdd = FIDO2KeyProvider.CanUse(DeviceKind.Portable);
			buttonHelloCleanup.Visible = canAdd && !FIDO2KeyProvider.UsesBrowser;
			portableButtons.Visible = set.Devices.Exists(r => r.Kind == DeviceKind.Classic);
			ShowStatus(canAdd ? Strings.DevicesTabInfo : Strings.WebAuthnUnavailableShort);
			SetEnabled(true, canAdd);
		}

		/// <summary>Device label; a classic device is marked: outside Windows it works only if it is a security key</summary>
		private static string DisplayName(DeviceRecord r)
		{
			string name = string.IsNullOrEmpty(r.Label) ? Strings.Unnamed : r.Label;
			return r.Kind == DeviceKind.Classic ? $"{name} {Strings.WindowsDeviceSuffix}" : name;
		}

		/// <summary>Phrase status; a single device without a phrase shows a warning about the risk of losing access</summary>
		private void UpdateRecoveryStatus()
		{
			buttonRecovery.Text = HasRecovery ? Strings.ReplacePhrase : Strings.CreateRecoveryPhrase;
			if (HasRecovery)
			{
				labelRecovery.ForeColor = SystemColors.ControlText;
				labelRecovery.Text = Strings.RecoveryPhraseCreated;
			}
			else if (set.Devices.Count == 1)
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

		private void SetEnabled(bool enabled, bool canAdd)
		{
			listBoxDevices.Enabled = enabled;
			textBoxDeviceName.Enabled = enabled && canAdd;
			buttonAddDevice.Enabled = enabled && canAdd;
			buttonRemoveDevice.Enabled = enabled && CanRemoveSelected();
			buttonMakePortable.Enabled = enabled && canAdd && SelectedIsClassic();
			buttonMakeAllPortable.Enabled = enabled && canAdd;
			buttonRecovery.Enabled = enabled;
			buttonRemoveRecovery.Enabled = enabled && HasRecovery;
		}

		/// <summary>Any device except the last one can be removed: without records the database cannot be opened</summary>
		private bool CanRemoveSelected()
		{
			int index = listBoxDevices.SelectedIndex;
			return index >= 0 && index < set.Devices.Count && set.Devices.Count > 1;
		}

		/// <summary>Only a classic device can be made portable; creating its new passkey needs what adding a device needs</summary>
		private bool SelectedIsClassic()
		{
			int index = listBoxDevices.SelectedIndex;
			return index >= 0 && index < set.Devices.Count && set.Devices[index].Kind == DeviceKind.Classic;
		}

		private void ShowStatus(string message)
		{
			labelStatus.Text = message;
		}

		/// <summary>
		/// Adding a device: new credential with PRF → K wrapped for it (bound to the database verification key)
		/// in the database header
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

			bool saved;
			try
			{
				PrfResult created = FIDO2KeyProvider.CreateCredentialForDatabase(
					FindForm(), database.IOConnectionInfo.Path, set.Devices);
				try
				{
					set.Devices.Add(new DeviceRecord
					{
						Kind = DeviceKind.Portable,
						CredentialId = created.CredentialId,
						Wrap = KeyWrap.Create(key, created.PrfSecret, set.VerificationKey),
						Label = label
					});
				}
				finally
				{
					MemUtil.ZeroByteArray(created.PrfSecret);
				}

				DeviceKeyStore.Save(database, set);
				saved = SaveDatabase();
				textBoxDeviceName.Clear();
			}
			catch (Exception ex)
			{
				MessageBox.Show(this, string.Format(Strings.AddDeviceFailed, ex.Message), "KeePassPasskeyKeyProvider",
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
				UpdateDeviceList();
				return;
			}
			finally
			{
				MemUtil.ZeroByteArray(key);
			}

			if (!saved) ShowNotSavedWarning();
		}

		/// <summary>
		/// Removing a device = database key rotation: otherwise the removed device would open
		/// the current file with its record left in its copies
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
				set.Devices.RemoveAt(index);
				FIDO2KeyProvider.RotateDatabaseKey(database, set);
				return SaveDatabase();
			});
		}

		/// <summary>Making the selected classic device portable: a new passkey on it replaces its record, K stays</summary>
		private void MakePortableButtonClick(object sender, EventArgs e)
		{
			if (SelectedIsClassic())
				MakePortable(new[] { set.Devices[listBoxDevices.SelectedIndex].CredentialId });
		}

		/// <summary>All classic devices one by one; Cancel stops, the devices made portable so far stay saved</summary>
		private void MakeAllPortableButtonClick(object sender, EventArgs e)
		{
			MakePortable(set.Devices.FindAll(r => r.Kind == DeviceKind.Classic).ConvertAll(r => r.CredentialId));
		}

		private void MakePortable(IList<byte[]> credentialIds)
		{
			DeviceMigration.Run(FindForm(), database, credentialIds, true, SaveDatabase);
			UpdateDeviceList();
		}

		private void HelloCleanupButtonClick(object sender, EventArgs e)
		{
			UIUtil.ShowDialogAndDestroy(new FIDO2OptionsForm(host));
		}

		/// <summary>
		/// Creating (replacing) the recovery phrase: K wrapped for the phrase in the database header. Replacement = revoking the old phrase,
		/// so rotation comes first: otherwise the old phrase plus its record from earlier file versions would yield K.
		/// </summary>
		private void RecoveryButtonClick(object sender, EventArgs e)
		{
			if (HasRecovery && MessageBox.Show(this,
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
					if (HasRecovery)
					{
						set.Recovery = null;
						FIDO2KeyProvider.RotateDatabaseKey(database, set);
					}

					byte[] key = FIDO2KeyProvider.GetDatabaseKey(database);
					byte[] secret = RecoveryPhrase.DeriveSecret(entropy);
					try
					{
						set.Recovery = KeyWrap.Create(key, secret, set.VerificationKey);
					}
					finally
					{
						MemUtil.ZeroByteArray(key);
						MemUtil.ZeroByteArray(secret);
					}
					DeviceKeyStore.Save(database, set);
					return SaveDatabase();
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
			if (!HasRecovery) return;

			if (MessageBox.Show(this,
				    Strings.RemovePhraseConfirm,
				    Strings.RemovePhraseTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
				return;

			RunBusy(Strings.RemovingPhrase, Strings.RemovePhraseFailed, () =>
			{
				set.Recovery = null;
				FIDO2KeyProvider.RotateDatabaseKey(database, set);
				return SaveDatabase();
			});
		}

		/// <summary>
		/// Runs the action under a busy indicator: saving the database (KDF) takes seconds and blocks the UI thread.
		/// The action returns whether the database was saved. On error — a message and re-reading the records from the database.
		/// </summary>
		private void RunBusy(string busyText, string errorText, Func<bool> action)
		{
			Exception error = null;
			bool saved = true;
			using (BusyIndicator.Show(this, busyText))
			{
				try
				{
					saved = action();
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
			else if (!saved)
				ShowNotSavedWarning();
		}

		/// <summary>Saves the database (see <see cref="KeePassPasskeyKeyProviderExt.SaveDatabase"/>) and refreshes the list</summary>
		/// <returns>false if the database has a file but still has unsaved changes (saving failed or was cancelled)</returns>
		private bool SaveDatabase()
		{
			bool saved = KeePassPasskeyKeyProviderExt.SaveDatabase(host, database);
			UpdateDeviceList();
			return saved;
		}

		private void ShowNotSavedWarning()
		{
			MessageBox.Show(this, Strings.ChangeNotSaved, "KeePassPasskeyKeyProvider",
			                MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}

		private void DevicesSelectedIndexChanged(object sender, EventArgs e)
		{
			buttonRemoveDevice.Enabled = CanRemoveSelected();
			buttonMakePortable.Enabled = canAdd && SelectedIsClassic();
		}
	}
}
