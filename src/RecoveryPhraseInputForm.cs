using System;
using System.Windows.Forms;

namespace KeePassFIDO2
{
	/// <summary>
	/// Ввод фразы восстановления для открытия базы без FIDO2‑устройства
	/// </summary>
	public partial class RecoveryPhraseInputForm : Form
	{
		public RecoveryPhraseInputForm()
		{
			InitializeComponent();
			labelDescription.Text =
				$"Введите {RecoveryPhrase.WordCount} слов фразы восстановления через пробел в исходном порядке. " +
				"Регистр не важен, слова можно сокращать до первых 4 букв.\n\n" +
				"После открытия базы добавьте новое устройство: Файл → Параметры базы → вкладка «FIDO2».";
		}

		/// <summary>Энтропия проверенной фразы (после «OK»); вызывающий обнуляет её после использования</summary>
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
