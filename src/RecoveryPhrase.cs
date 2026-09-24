using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Фраза восстановления: 128 бит случайной энтропии в виде 12 слов BIP39 (английский словарь,
	/// 4 бита SHA‑256 — контрольная сумма от опечаток). Секрет фразы R = HMAC‑SHA256(энтропия, метка);
	/// в заголовке базы хранится K ⊕ R — так же, как обёртка устройства (см. <see cref="DeviceKeyStore"/>).
	/// </summary>
	public static class RecoveryPhrase
	{
		// ВАЖНО: метка и схема вывода — часть «формата» базы: их изменение делает выданные фразы недействительными
		private static readonly byte[] DerivationLabel = Encoding.ASCII.GetBytes("KeePassFIDO2 recovery phrase v1");
		private const string WordListResource = "KeePassPasskeyKeyProvider.bip39-english.txt";

		private const int EntropyLength = 16;
		public const int WordCount = 12;
		private const int BitsPerWord = 11;
		private const int UniquePrefixLength = 4; // в словаре BIP39 слова различимы по первым 4 буквам

		private static string[] wordList;

		private static string[] WordList
		{
			get
			{
				if (wordList != null) return wordList;

				using (Stream s = typeof(RecoveryPhrase).Assembly.GetManifestResourceStream(WordListResource))
				using (var reader = new StreamReader(s, Encoding.ASCII))
				{
					string[] words = reader.ReadToEnd().Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
					if (words.Length != 1 << BitsPerWord)
						throw new InvalidDataException("Повреждён словарь BIP39");
					return wordList = words;
				}
			}
		}

		public static byte[] GenerateEntropy()
		{
			byte[] entropy = new byte[EntropyLength];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(entropy);
			return entropy;
		}

		/// <summary>Энтропия → 12 слов</summary>
		public static string[] ToWords(byte[] entropy)
		{
			if (entropy == null || entropy.Length != EntropyLength)
				throw new ArgumentException($"Ожидается {EntropyLength} байт энтропии");

			byte[] bits = AppendChecksum(entropy);
			try
			{
				var words = new string[WordCount];
				for (int w = 0; w < WordCount; w++)
				{
					int index = 0;
					for (int b = 0; b < BitsPerWord; b++)
						index = (index << 1) | GetBit(bits, w * BitsPerWord + b);
					words[w] = WordList[index];
				}
				return words;
			}
			finally
			{
				MemUtil.ZeroByteArray(bits);
			}
		}

		/// <summary>
		/// Текст фразы → энтропия. Регистр и разделители не важны, слово можно сократить до первых 4 букв.
		/// </summary>
		/// <exception cref="FormatException">Сообщение для пользователя: число слов, неизвестное слово, контрольная сумма</exception>
		public static byte[] FromText(string text)
		{
			string[] words = (text ?? string.Empty).ToLowerInvariant()
				.Split(new[] { ' ', '\t', '\r', '\n', ',', ';', '.' }, StringSplitOptions.RemoveEmptyEntries);
			if (words.Length != WordCount)
				throw new FormatException($"Фраза должна состоять из {WordCount} слов (введено: {words.Length}).");

			byte[] bits = new byte[EntropyLength + 1];
			try
			{
				for (int w = 0; w < WordCount; w++)
				{
					int index = FindWord(words[w]);
					if (index < 0)
						throw new FormatException($"Слово №{w + 1} «{words[w]}» не из словаря фразы восстановления.");
					for (int b = 0; b < BitsPerWord; b++)
						SetBit(bits, w * BitsPerWord + b, (index >> (BitsPerWord - 1 - b)) & 1);
				}

				byte[] entropy = new byte[EntropyLength];
				Array.Copy(bits, entropy, EntropyLength);
				byte[] expected = AppendChecksum(entropy);
				bool valid = expected[EntropyLength] == bits[EntropyLength];
				MemUtil.ZeroByteArray(expected);
				if (!valid)
				{
					MemUtil.ZeroByteArray(entropy);
					throw new FormatException("Фраза введена с ошибкой: не сходится контрольная сумма. " +
					                          "Проверьте слова и их порядок.");
				}
				return entropy;
			}
			finally
			{
				MemUtil.ZeroByteArray(bits);
			}
		}

		/// <summary>Секрет фразы R (32 байта), которым оборачивается ключ базы</summary>
		public static byte[] DeriveSecret(byte[] entropy)
		{
			using (var hmac = new HMACSHA256(entropy))
				return hmac.ComputeHash(DerivationLabel);
		}

		private static int FindWord(string word)
		{
			int index = Array.IndexOf(WordList, word);
			if (index >= 0 || word.Length < UniquePrefixLength) return index;
			return Array.FindIndex(WordList, w => w.StartsWith(word, StringComparison.Ordinal));
		}

		/// <summary>Энтропия + первые 4 бита SHA‑256 от неё (в старших битах последнего байта)</summary>
		private static byte[] AppendChecksum(byte[] entropy)
		{
			byte[] result = new byte[EntropyLength + 1];
			Array.Copy(entropy, result, EntropyLength);
			using (var sha = SHA256.Create())
				result[EntropyLength] = (byte)(sha.ComputeHash(entropy)[0] & 0xF0);
			return result;
		}

		private static int GetBit(byte[] data, int bit)
		{
			return (data[bit >> 3] >> (7 - (bit & 7))) & 1;
		}

		private static void SetBit(byte[] data, int bit, int value)
		{
			if (value != 0) data[bit >> 3] |= (byte)(0x80 >> (bit & 7));
		}

		/// <summary>Нумерованная раскладка слов в 3 столбца (для показа и печати)</summary>
		public static string Format(IList<string> words)
		{
			const int columns = 3;
			int rows = (words.Count + columns - 1) / columns;
			var sb = new StringBuilder();
			for (int r = 0; r < rows; r++)
			{
				for (int c = 0; c < columns; c++)
				{
					int i = c * rows + r;
					if (i < words.Count) sb.Append($"{i + 1,2}. {words[i],-10}");
				}
				sb.AppendLine();
			}
			return sb.ToString().TrimEnd();
		}
	}
}
