using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Recovery phrase: 128 bits of random entropy as 12 BIP39 words (English wordlist,
	/// 4 bits of SHA‑256 as a checksum against typos). Phrase secret R = HMAC‑SHA256(entropy, label);
	/// the database header stores K ⊕ R, like a device wrapped key (see <see cref="DeviceKeyStore"/>).
	/// </summary>
	public static class RecoveryPhrase
	{
		// IMPORTANT: the label and derivation scheme are part of the database "format": changing them invalidates issued phrases
		private static readonly byte[] DerivationLabel = Encoding.ASCII.GetBytes("KeePassFIDO2 recovery phrase v1");
		private const string WordListResource = "KeePassPasskeyKeyProvider.bip39-english.txt";

		private const int EntropyLength = 16;
		public const int WordCount = 12;
		private const int BitsPerWord = 11;
		private const int UniquePrefixLength = 4; // BIP39 words are distinguishable by their first 4 letters

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
						throw new InvalidDataException("BIP39 wordlist is corrupted");
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

		/// <summary>Entropy → 12 words</summary>
		public static string[] ToWords(byte[] entropy)
		{
			if (entropy == null || entropy.Length != EntropyLength)
				throw new ArgumentException($"Expected {EntropyLength} bytes of entropy");

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
		/// Phrase text → entropy. Case and separators don't matter; a word can be shortened to its first 4 letters.
		/// </summary>
		/// <exception cref="FormatException">User-facing message: word count, unknown word, checksum</exception>
		public static byte[] FromText(string text)
		{
			string[] words = (text ?? string.Empty).ToLowerInvariant()
				.Split(new[] { ' ', '\t', '\r', '\n', ',', ';', '.' }, StringSplitOptions.RemoveEmptyEntries);
			if (words.Length != WordCount)
				throw new FormatException($"The phrase must consist of {WordCount} words (entered: {words.Length}).");

			byte[] bits = new byte[EntropyLength + 1];
			try
			{
				for (int w = 0; w < WordCount; w++)
				{
					int index = FindWord(words[w]);
					if (index < 0)
						throw new FormatException($"Word #{w + 1} \"{words[w]}\" is not in the recovery phrase wordlist.");
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
					throw new FormatException("The phrase contains an error: checksum mismatch. " +
					                          "Check the words and their order.");
				}
				return entropy;
			}
			finally
			{
				MemUtil.ZeroByteArray(bits);
			}
		}

		/// <summary>Phrase secret R (32 bytes) used to wrap the database key</summary>
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

		/// <summary>Entropy + first 4 bits of its SHA‑256 (in the high bits of the last byte)</summary>
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

		/// <summary>Numbered word layout in 3 columns (for display and printing)</summary>
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
