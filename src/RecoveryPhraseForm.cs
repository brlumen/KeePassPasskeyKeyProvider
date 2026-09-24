using System;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Shows a new recovery phrase and verifies that the user wrote it down:
	/// step 1 — the words, step 2 — entering three random words by number (the words are hidden)
	/// </summary>
	public partial class RecoveryPhraseForm : Form
	{
		private const int CheckedWordCount = 3;

		private readonly string[] words;
		private readonly int[] checkedPositions;
		private readonly Label[] checkLabels;
		private readonly TextBox[] checkBoxes;

		public RecoveryPhraseForm(string[] words)
		{
			InitializeComponent();
			this.words = words;
			checkedPositions = PickPositions();
			checkLabels = new[] { labelWord1, labelWord2, labelWord3 };
			checkBoxes = new[] { textBoxWord1, textBoxWord2, textBoxWord3 };

			textBoxWords.Text = RecoveryPhrase.Format(words);
			for (int i = 0; i < CheckedWordCount; i++)
				checkLabels[i].Text = string.Format(Strings.WordNumber, checkedPositions[i] + 1);

			ShowWords();
		}

		/// <summary>Three distinct word numbers in ascending order</summary>
		private int[] PickPositions()
		{
			var positions = Enumerable.Range(0, words.Length).ToList();
			var picked = new int[CheckedWordCount];
			byte[] random = new byte[CheckedWordCount];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(random);

			for (int i = 0; i < CheckedWordCount; i++)
			{
				int index = random[i] % positions.Count;
				picked[i] = positions[index];
				positions.RemoveAt(index);
			}
			Array.Sort(picked);
			return picked;
		}

		private void ShowWords()
		{
			labelDescription.Text = Strings.RecoveryPhraseInstructions;
			textBoxWords.Visible = true;
			panelCheck.Visible = false;
			labelError.Text = string.Empty;
			buttonBack.Visible = false;
			buttonNext.Text = Strings.IWroteItDown;
		}

		private void ShowCheck()
		{
			labelDescription.Text = Strings.VerifyPhraseDescription;
			textBoxWords.Visible = false;
			panelCheck.Visible = true;
			buttonBack.Visible = true;
			buttonNext.Text = Strings.Done;
			foreach (TextBox box in checkBoxes)
				box.Clear();
			checkBoxes[0].Focus();
		}

		private void NextButtonClick(object sender, EventArgs e)
		{
			if (textBoxWords.Visible)
			{
				ShowCheck();
				return;
			}

			for (int i = 0; i < CheckedWordCount; i++)
			{
				if (!string.Equals(checkBoxes[i].Text.Trim(), words[checkedPositions[i]], StringComparison.OrdinalIgnoreCase))
				{
					labelError.Text = string.Format(Strings.WordMismatch, checkedPositions[i] + 1);
					checkBoxes[i].Focus();
					checkBoxes[i].SelectAll();
					return;
				}
			}
			DialogResult = DialogResult.OK;
		}

		private void BackButtonClick(object sender, EventArgs e)
		{
			ShowWords();
		}
	}
}
