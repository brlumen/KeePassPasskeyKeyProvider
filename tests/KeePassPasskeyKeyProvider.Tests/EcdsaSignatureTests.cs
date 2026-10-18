using System;
using System.Security.Cryptography;
using KeePassPasskeyKeyProvider.Ecc;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class EcdsaSignatureTests
	{
		[TestMethod]
		public void ToDerEncodesMinimalIntegers()
		{
			// r has the high bit set (needs a zero byte), s is 31 bytes long with the high bit set
			CollectionAssert.AreEqual(TestData.FromHex(Vectors.Der), EcdsaSignature.ToDer(TestData.FromHex(Vectors.P1363)));
		}

		[TestMethod]
		public void FromDerRestoresFixedLengthIntegers()
		{
			CollectionAssert.AreEqual(TestData.FromHex(Vectors.P1363), EcdsaSignature.FromDer(TestData.FromHex(Vectors.Der)));
		}

		[DataTestMethod]
		[DataRow("0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
		[DataRow("00000000000000000000000000000000000000000000000000000000000000017f00000000000000000000000000000000000000000000000000000000000000")]
		public void RoundTrips(string signature)
		{
			byte[] p1363 = TestData.FromHex(signature);

			CollectionAssert.AreEqual(p1363, EcdsaSignature.FromDer(EcdsaSignature.ToDer(p1363)));
		}

		[TestMethod]
		public void FromDerRejectsMalformedInput()
		{
			byte[] der = TestData.FromHex(Vectors.Der);
			byte[] truncated = new byte[der.Length - 1];
			Array.Copy(der, truncated, truncated.Length);
			byte[] trailing = new byte[der.Length + 1];
			Array.Copy(der, trailing, der.Length);
			byte[] wrongTag = (byte[])der.Clone();
			wrongTag[2] = 0x03;
			byte[] tooLong = TestData.FromHex("30260221" + "01" + new string('0', 64) + "020100");

			Assert.ThrowsException<CryptographicException>(() => EcdsaSignature.FromDer(truncated));
			Assert.ThrowsException<CryptographicException>(() => EcdsaSignature.FromDer(trailing));
			Assert.ThrowsException<CryptographicException>(() => EcdsaSignature.FromDer(wrongTag));
			Assert.ThrowsException<CryptographicException>(() => EcdsaSignature.FromDer(tooLong));
		}

		internal static class Vectors
		{
			// Made by OpenSSL: an implementation independent of the platform ones
			public const string PublicKey = "04b37d70e453050d5197c2a155bd85e40bbd9b283c364dc6af823e86d9c88b42c1f78ed8050039d41eb0c16eec1b7154bea275eaeab04a787c689daf358f034152";
			public const string Data = "KeePassPasskeyKeyProvider signature vector";
			public const string P1363 = "862926203fa56a28cf568b028f05678cfd295fb2a958720e5d301793834fbdcf008658ef9d0f23d9bdf3fbc060628763ab8af27dc1535200b12e3e1d9d8fd5a3";
			public const string Der = "3045022100862926203fa56a28cf568b028f05678cfd295fb2a958720e5d301793834fbdcf0220008658ef9d0f23d9bdf3fbc060628763ab8af27dc1535200b12e3e1d9d8fd5a3";
		}
	}
}
