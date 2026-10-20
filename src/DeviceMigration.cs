using System;
using System.Collections.Generic;
using System.Windows.Forms;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Makes classic devices portable (see <see cref="DeviceKind"/>): the RP ID of a passkey cannot change, so a new
	/// portable passkey is created on the same authenticator and replaces the classic one in its record
	/// (<see cref="FIDO2KeyProvider.ReplaceWithPortable"/>). The old passkey stays on the authenticator.
	/// </summary>
	internal static class DeviceMigration
	{
		private const string Caption = "KeePassPasskeyKeyProvider";

		/// <summary>
		/// Makes the classic devices with the credential IDs portable one by one, saving the database after each.
		/// Stops when the user cancels or a step fails; the replacements made so far stay.
		/// </summary>
		/// <param name="confirmEach">Ask before each device; false when the user has just chosen to migrate this device</param>
		/// <param name="save">Saves the database; false if it still has unsaved changes</param>
		/// <returns>Whether a device was made portable</returns>
		public static bool Run(Form owner, PwDatabase db, IList<byte[]> credentialIds, bool confirmEach, Func<bool> save)
		{
			bool migrated = false;
			try
			{
				// Plugin versions before portable devices cannot read the records afterwards
				if (!DeviceKeyStore.UsesVersion5(DeviceKeyStore.LoadAll(db)) && !Confirm(owner, Strings.MakePortableVersionWarning))
					return false;

				foreach (byte[] credentialId in credentialIds)
				{
					DeviceRecordSet set = DeviceKeyStore.LoadAll(db);
					int index = set.Devices.FindIndex(r => r.Kind == DeviceKind.Classic && MemUtil.ArraysEqual(r.CredentialId, credentialId));
					if (index < 0)
						continue;

					string label = string.IsNullOrEmpty(set.Devices[index].Label) ? Strings.Unnamed : set.Devices[index].Label;
					if (confirmEach && !Confirm(owner, string.Format(Strings.MakePortableConfirm, label, SameDevice)))
						break;

					PrfResult created = FIDO2KeyProvider.CreateCredentialForDatabase(owner, db.IOConnectionInfo.Path, set.Devices);
					try
					{
						FIDO2KeyProvider.ReplaceWithPortable(db, set, index, created);
					}
					finally
					{
						MemUtil.ZeroByteArray(created.PrfSecret);
					}

					migrated = true;
					if (!save())
					{
						MessageBox.Show(owner, Strings.ChangeNotSaved, Caption, MessageBoxButtons.OK, MessageBoxIcon.Warning);
						return true;
					}
				}
			}
			catch (Exception ex)
			{
				MessageBox.Show(owner, string.Format(Strings.MakePortableFailed, ex.Message), Caption,
				                MessageBoxButtons.OK, MessageBoxIcon.Error);
			}

			if (migrated)
			{
				string done = FIDO2KeyProvider.UsesBrowser
					? Strings.MakePortableDone
					: Strings.MakePortableDone + "\n" + Strings.MakePortableDoneHello;
				MessageBox.Show(owner, done, Caption, MessageBoxButtons.OK, MessageBoxIcon.Information);
			}
			return migrated;
		}

		/// <summary>Which authenticator to confirm with, in the words of this system's dialog</summary>
		public static string SameDevice => FIDO2KeyProvider.UsesBrowser ? Strings.MakePortableSameDeviceBrowser : Strings.MakePortableSameDevice;

		private static bool Confirm(IWin32Window owner, string text)
		{
			return MessageBox.Show(owner, text, Caption, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK;
		}
	}
}
