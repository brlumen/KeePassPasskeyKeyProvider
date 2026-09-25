using System;
using System.Security.Cryptography;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Per-database ECDSA P‑256 key pair that signs the device records (see <see cref="DeviceKeyStore"/>).
	/// The verification key VK (0x04 ‖ X ‖ Y) is public and stored with the records; the private scalar
	/// is stored only in the encrypted part of the database.
	/// </summary>
	public sealed class SigningKey : IDisposable
	{
		public const int SignatureLength = 2 * KeyWrap.KeyLength; // IEEE P1363: r ‖ s

		private byte[] privateKey;

		private SigningKey(byte[] verificationKey, byte[] privateKey)
		{
			VerificationKey = verificationKey;
			this.privateKey = privateKey;
		}

		public byte[] VerificationKey { get; }

		public static SigningKey Generate()
		{
			using (ECDsa ecdsa = ECDsa.Create(KeyWrap.Curve))
			{
				ECParameters p = ecdsa.ExportParameters(true);
				return new SigningKey(KeyWrap.EncodePoint(p.Q), p.D);
			}
		}

		/// <summary>Key pair from the stored private scalar; checks that it belongs to the verification key</summary>
		/// <exception cref="CryptographicException">The private key does not match the verification key</exception>
		public static SigningKey Import(byte[] privateKey, byte[] verificationKey)
		{
			var key = new SigningKey((byte[])verificationKey.Clone(), privateKey);
			try
			{
				byte[] probe = new byte[KeyWrap.KeyLength];
				using (var rng = new RNGCryptoServiceProvider())
					rng.GetBytes(probe);
				if (!Verify(verificationKey, probe, key.Sign(probe)))
					throw new CryptographicException("The signing key does not match the verification key");
				return key;
			}
			catch
			{
				key.Dispose();
				throw;
			}
		}

		public byte[] ExportPrivateKey()
		{
			return (byte[])privateKey.Clone();
		}

		public SigningKey Clone()
		{
			return new SigningKey((byte[])VerificationKey.Clone(), ExportPrivateKey());
		}

		public byte[] Sign(byte[] data)
		{
			var p = new ECParameters { Curve = KeyWrap.Curve, Q = KeyWrap.DecodePoint(VerificationKey), D = (byte[])privateKey.Clone() };
			try
			{
				using (ECDsa ecdsa = ECDsa.Create(p))
					return ecdsa.SignData(data, HashAlgorithmName.SHA256);
			}
			finally
			{
				MemUtil.ZeroByteArray(p.D);
			}
		}

		public static bool Verify(byte[] verificationKey, byte[] data, byte[] signature)
		{
			if (signature == null || signature.Length != SignatureLength) return false;
			try
			{
				var p = new ECParameters { Curve = KeyWrap.Curve, Q = KeyWrap.DecodePoint(verificationKey) };
				using (ECDsa ecdsa = ECDsa.Create(p))
					return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
			}
			catch (CryptographicException)
			{
				return false; // not a point on the curve
			}
		}

		public void Dispose()
		{
			if (privateKey == null) return;
			MemUtil.ZeroByteArray(privateKey);
			privateKey = null;
		}
	}
}
