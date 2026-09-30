using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class KeyWrapTests
	{
		private readonly byte[] key = TestData.Random(KeyWrap.KeyLength);
		private readonly byte[] secret = TestData.Random(KeyWrap.KeyLength);
		private readonly byte[] verificationKey = SigningKey.Generate().VerificationKey;

		[TestMethod]
		public void OpenReturnsWrappedKey()
		{
			KeyWrap wrap = KeyWrap.Create(key, secret, verificationKey);

			CollectionAssert.AreEqual(key, wrap.Open(secret, verificationKey));
		}

		[TestMethod]
		public void OpenRejectsWrongSecret()
		{
			KeyWrap wrap = KeyWrap.Create(key, secret, verificationKey);

			Assert.ThrowsException<CryptographicException>(() => wrap.Open(TestData.Random(KeyWrap.KeyLength), verificationKey));
		}

		[TestMethod]
		public void OpenRejectsOtherVerificationKey()
		{
			KeyWrap wrap = KeyWrap.Create(key, secret, verificationKey);

			Assert.ThrowsException<CryptographicException>(() => wrap.Open(secret, SigningKey.Generate().VerificationKey));
		}

		[TestMethod]
		public void OpenRejectsOwnerTagMovedToAnotherWrap()
		{
			// A forger keeps the victim's owner tag but substitutes an owner key pair wrapping the forger's key
			byte[] original = TestData.Serialize(KeyWrap.Create(key, secret, verificationKey));
			byte[] forged = TestData.Serialize(KeyWrap.Create(TestData.Random(KeyWrap.KeyLength), TestData.Random(KeyWrap.KeyLength), verificationKey));
			int tagOffset = KeyWrap.SerializedLength - KeyWrap.KeyLength;
			Array.Copy(original, tagOffset, forged, tagOffset, KeyWrap.KeyLength);

			Assert.ThrowsException<CryptographicException>(() => TestData.Deserialize(forged).Open(secret, verificationKey));
		}

		[TestMethod]
		public void SealReplacesKeyWithoutSecret()
		{
			KeyWrap wrap = KeyWrap.Create(key, secret, verificationKey);
			byte[] oldWrap = TestData.Serialize(wrap);
			byte[] newKey = TestData.Random(KeyWrap.KeyLength);

			wrap.Seal(newKey);

			CollectionAssert.AreEqual(newKey, wrap.Open(secret, verificationKey));
			CollectionAssert.AreEqual(key, TestData.Deserialize(oldWrap).Open(secret, verificationKey));
		}

		[TestMethod]
		public void SerializationRoundTrips()
		{
			byte[] data = TestData.Serialize(KeyWrap.Create(key, secret, verificationKey));

			Assert.AreEqual(KeyWrap.SerializedLength, data.Length);
			CollectionAssert.AreEqual(key, TestData.Deserialize(data).Open(secret, verificationKey));
		}

		[TestMethod]
		public void OpensWrapOfPreviousRelease()
		{
			// Format invariant: a wrap produced by v1.0.0; a change of the KDF, tag label or layout breaks existing databases
			KeyWrap wrap = TestData.Deserialize(TestData.FromHex(Vectors.Wrap));

			Assert.AreEqual(Vectors.Key, TestData.ToHex(wrap.Open(TestData.FromHex(Vectors.Secret), TestData.FromHex(Vectors.VerificationKey))));
		}

		[TestMethod]
		public void ReadRejectsTruncatedData()
		{
			byte[] data = TestData.Serialize(KeyWrap.Create(key, secret, verificationKey));
			Array.Resize(ref data, data.Length - 1);

			Assert.ThrowsException<EndOfStreamException>(() => TestData.Deserialize(data));
		}

		[TestMethod]
		public void ReadRejectsCompressedPoint()
		{
			byte[] data = TestData.Serialize(KeyWrap.Create(key, secret, verificationKey));
			data[0] = 0x02;

			Assert.ThrowsException<InvalidDataException>(() => TestData.Deserialize(data));
		}

		[TestMethod]
		public void OpenRejectsEphemeralKeyNotOnCurve()
		{
			byte[] data = TestData.Serialize(KeyWrap.Create(key, secret, verificationKey));
			data[KeyWrap.PublicKeyLength + KeyWrap.KeyLength + 1] ^= 1;

			Assert.ThrowsException<CryptographicException>(() => TestData.Deserialize(data).Open(secret, verificationKey));
		}

		[TestMethod]
		public void CreateRejectsWrongLengths()
		{
			Assert.ThrowsException<ArgumentException>(() => KeyWrap.Create(new byte[16], secret, verificationKey));
			Assert.ThrowsException<ArgumentException>(() => KeyWrap.Create(key, new byte[16], verificationKey));
			Assert.ThrowsException<ArgumentException>(() => KeyWrap.Create(key, secret, new byte[33]));
		}

		private static class Vectors
		{
			public const string Key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
			public const string Secret = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
			public const string VerificationKey = "04a9a81db81b886b124ef845aa3677e4a3870482c320ad819b637d59d753b8ed8359555ffd8802ce83e6b6f53294d89c452881bdb43991c593d0c52429696457eb";
			public const string Wrap = "044245369ad1a5a69edb7469fb2f3f79d34e39fd6da820f152d0c7e2eeb281ce20af4c7fbca3ba2fa27b4ebfea8d54d32357e9fdb9b1dcaec959835a79c570fe42a279067361ae0e8b4402406c053e6fc065c084f47c86f4a908b9c2db773225310427b728f500d613cbb91fa110f9fa7f36909a0825960036e836b497a3e4efcb49f7b5091c05eb962b5f17f5628228f7f0a051528102ccf67ae5edf99a3468434ebfaeb7378b39dc976c6845937b9fdd6829d30dfc430e4819fa3c2ac92f3adf4901d50cb9707367fb2d39c5b3fd6ca575ed7e5c78a9e55c4094a4dee0fef2d11e";
		}
	}
}
