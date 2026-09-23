using System;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace KeePassFIDO2
{
	/// <summary>
	/// Показ новой фразы восстановления и проверка, что пользователь её записал:
	/// шаг 1 — слова, шаг 2 — ввод трёх случайных слов по номерам (сами слова скрыты)
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
				checkLabels[i].Text = $"Слово №{checkedPositions[i] + 1}:";

			ShowWords();
		}

		/// <summary>Три разных номера слов по возрастанию</summary>
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
			labelDescription.Text =
				"Запишите фразу восстановления на бумаге и храните её в надёжном месте.\n\n" +
				"Фраза открывает базу без FIDO2‑устройства (если в мастер‑ключе есть пароль — вместе с ним). " +
				"Не храните её в файлах, облаке или фотографиях. Потерянную или скомпрометированную фразу " +
				"удалите на вкладке «FIDO2» — мастер‑ключ базы будет заменён.\n\n" +
				"Фраза показывается только сейчас: посмотреть её позже будет невозможно.";
			textBoxWords.Visible = true;
			panelCheck.Visible = false;
			labelError.Text = string.Empty;
			buttonBack.Visible = false;
			buttonNext.Text = "Я записал фразу";
		}

		private void ShowCheck()
		{
			labelDescription.Text = "Для проверки введите слова фразы с указанными номерами.";
			textBoxWords.Visible = false;
			panelCheck.Visible = true;
			buttonBack.Visible = true;
			buttonNext.Text = "Готово";
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
					labelError.Text = $"Слово №{checkedPositions[i] + 1} не совпадает. Нажмите «Назад», чтобы посмотреть фразу ещё раз.";
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
