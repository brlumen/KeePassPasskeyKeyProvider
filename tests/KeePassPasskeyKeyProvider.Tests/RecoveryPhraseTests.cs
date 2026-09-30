using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class RecoveryPhraseTests
	{
		// BIP39 test vectors (128-bit entropy) from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
		[DataTestMethod]
		[DataRow("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")]
		[DataRow("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow")]
		[DataRow("80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above")]
		[DataRow("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")]
		[DataRow("9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic")]
		public void MatchesBip39Vectors(string entropyHex, string phrase)
		{
			byte[] entropy = TestData.FromHex(entropyHex);

			Assert.AreEqual(phrase, string.Join(" ", RecoveryPhrase.ToWords(entropy)));
			CollectionAssert.AreEqual(entropy, RecoveryPhrase.FromText(phrase));
		}

		[TestMethod]
		public void RandomPhraseRoundTrips()
		{
			byte[] entropy = RecoveryPhrase.GenerateEntropy();
			string[] words = RecoveryPhrase.ToWords(entropy);

			Assert.AreEqual(RecoveryPhrase.WordCount, words.Length);
			CollectionAssert.AreEqual(entropy, RecoveryPhrase.FromText(string.Join(" ", words)));
		}

		[TestMethod]
		public void FromTextIgnoresCaseAndSeparatorsAndAcceptsPrefixes()
		{
			CollectionAssert.AreEqual(
				TestData.FromHex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
				RecoveryPhrase.FromText("  LEGA, winn; thank\tyear\r\nwave. saus worth usef legal winner thank YELL "));
		}

		[DataTestMethod]
		[DataRow("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")] // checksum
		[DataRow("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")] // 11 words
		[DataRow("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon qwerty")] // unknown word
		[DataRow("aba abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")] // prefix too short
		[DataRow("")]
		public void FromTextRejectsInvalidPhrase(string text)
		{
			Assert.ThrowsException<FormatException>(() => RecoveryPhrase.FromText(text));
		}

		[TestMethod]
		public void DerivedSecretIsStable()
		{
			// Format invariant: changing the derivation makes issued recovery phrases useless
			byte[] secret = RecoveryPhrase.DeriveSecret(TestData.FromHex("00000000000000000000000000000000"));

			Assert.AreEqual("9feedfa9c5bf5fa66bcd2510d1a3e1283c4eb516d9337cc196b5fb53c517e729", TestData.ToHex(secret));
		}
	}
}
