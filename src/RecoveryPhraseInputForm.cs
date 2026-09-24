using System;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Recovery phrase input for opening the database without a FIDO2 device
	/// </summary>
	public partial class RecoveryPhraseInputForm : Form
	{
		public RecoveryPhraseInputForm()
		{
			InitializeComponent();
			labelDescription.Text =
				$"Enter the {RecoveryPhrase.WordCount} recovery phrase words separated by spaces in the original order. " +
				"Case does not matter; words can be shortened to their first 4 letters.\n\n" +
				"After opening the database, add a new device: File → Database Settings → \"FIDO2\" tab.";
		}

		/// <summary>Entropy of the verified phrase (after "OK"); the caller zeroes it after use</summary>
		public byte[] Entropy { get; private set; }

		private void OkButtonClick(object sender, EventArgs e)
		{
			try
			{
				Entropy = RecoveryPhrase.FromText(textBoxPhrase.Text);
			}
			catch (FormatException ex)
			{
				labelError.Text = ex.Message;
				textBoxPhrase.Focus();
				return;
			}

			textBoxPhrase.Clear();
			DialogResult = DialogResult.OK;
		}
	}
}
