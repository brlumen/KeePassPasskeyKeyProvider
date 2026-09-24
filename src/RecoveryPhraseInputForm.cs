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
			labelDescription.Text = string.Format(Strings.RecoveryInputDescription, RecoveryPhrase.WordCount);
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
