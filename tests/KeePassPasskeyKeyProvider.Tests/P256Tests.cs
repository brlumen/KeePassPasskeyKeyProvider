using System.Security.Cryptography;
using System.Text;
using KeePassPasskeyKeyProvider.Ecc;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	/// <summary>Contract of the platform P‑256 backend (CNG on Windows, OpenSSL elsewhere)</summary>
	[TestClass]
	public class P256Tests
	{
		private static readonly byte[] Label = Encoding.ASCII.GetBytes(Vectors.Label);

		[TestMethod]
		public void DeriveKeyFromHashMatchesKnownVector()
		{
			byte[] key = P256.Current.DeriveKeyFromHash(TestData.FromHex(Vectors.PrivateKey), TestData.FromHex(Vectors.PublicKey),
				TestData.FromHex(Vectors.PeerPublicKey), Label);

			Assert.AreEqual(Vectors.DerivedKey, TestData.ToHex(key));
		}

		[TestMethod]
		public void RejectsPublicKeyNotOnCurve()
		{
			byte[] privateKey = TestData.FromHex(Vectors.PrivateKey);
			byte[] publicKey = TestData.FromHex(Vectors.PublicKey);
			byte[] notOnCurve = (byte[])publicKey.Clone();
			notOnCurve[P256.PublicKeyLength - 1] ^= 1;

			Assert.ThrowsException<CryptographicException>(() => P256.Current.VerifyData(notOnCurve, Label, new byte[P256.SignatureLength]));
			Assert.ThrowsException<CryptographicException>(() => P256.Current.SignData(privateKey, notOnCurve, Label));
			Assert.ThrowsException<CryptographicException>(() => P256.Current.DeriveKeyFromHash(privateKey, publicKey, notOnCurve, Label));
			Assert.ThrowsException<CryptographicException>(() => P256.Current.DeriveEphemeralKeyFromHash(notOnCurve, Label, out _));
		}

		private static class Vectors
		{
			// NIST CAVS ECC CDH primitive test vector (P‑256, COUNT = 0): dIUT, QIUT, QCAVS
			public const string PrivateKey = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
			public const string PublicKey = "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141";
			public const string PeerPublicKey = "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
			public const string Label = "KeePassPasskeyKeyProvider ECDH vector";
			// SHA‑256(ZIUT ‖ label), ZIUT = 46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b
			public const string DerivedKey = "f4a9070c80c449988248123cfdd0346a50a946c4d1cddc259084d236dd8c7770";
		}
	}
}
