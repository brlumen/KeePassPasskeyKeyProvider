using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class SigningKeyTests
	{
		private readonly byte[] data = TestData.Random(100);

		[TestMethod]
		public void SignatureVerifies()
		{
			using (SigningKey sk = SigningKey.Generate())
				Assert.IsTrue(SigningKey.Verify(sk.VerificationKey, data, sk.Sign(data)));
		}

		[TestMethod]
		public void VerifyRejectsModifiedData()
		{
			using (SigningKey sk = SigningKey.Generate())
			{
				byte[] signature = sk.Sign(data);
				data[0] ^= 1;

				Assert.IsFalse(SigningKey.Verify(sk.VerificationKey, data, signature));
			}
		}

		[TestMethod]
		public void VerifyRejectsOtherKey()
		{
			using (SigningKey sk = SigningKey.Generate())
			using (SigningKey other = SigningKey.Generate())
				Assert.IsFalse(SigningKey.Verify(other.VerificationKey, data, sk.Sign(data)));
		}

		[TestMethod]
		public void VerifyRejectsMalformedInput()
		{
			using (SigningKey sk = SigningKey.Generate())
			{
				byte[] signature = sk.Sign(data);
				byte[] notOnCurve = (byte[])sk.VerificationKey.Clone();
				notOnCurve[1] ^= 1;

				Assert.IsFalse(SigningKey.Verify(sk.VerificationKey, data, null));
				Assert.IsFalse(SigningKey.Verify(sk.VerificationKey, data, new byte[SigningKey.SignatureLength - 1]));
				Assert.IsFalse(SigningKey.Verify(notOnCurve, data, signature));
			}
		}

		[TestMethod]
		public void ImportRestoresKey()
		{
			using (SigningKey sk = SigningKey.Generate())
			using (SigningKey imported = SigningKey.Import(sk.ExportPrivateKey(), sk.VerificationKey))
				Assert.IsTrue(SigningKey.Verify(sk.VerificationKey, data, imported.Sign(data)));
		}

		[TestMethod]
		public void ImportRejectsMismatchedKey()
		{
			using (SigningKey sk = SigningKey.Generate())
			using (SigningKey other = SigningKey.Generate())
				Assert.ThrowsException<CryptographicException>(() => SigningKey.Import(other.ExportPrivateKey(), sk.VerificationKey));
		}
	}
}
