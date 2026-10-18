using System;
using System.Security.Cryptography;
using KeePassLib.Utility;
using KeePassPasskeyKeyProvider.Ecc;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Per-database ECDSA P‑256 key pair that signs the device records (see <see cref="DeviceKeyStore"/>).
	/// The verification key VK (0x04 ‖ X ‖ Y) is public and stored with the records; the private scalar
	/// is stored only in the encrypted part of the database.
	/// </summary>
	public sealed class SigningKey : IDisposable
	{
		public const int SignatureLength = P256.SignatureLength;

		private byte[] privateKey;

		private SigningKey(byte[] verificationKey, byte[] privateKey)
		{
			VerificationKey = verificationKey;
			this.privateKey = privateKey;
		}

		public byte[] VerificationKey { get; }

		public static SigningKey Generate()
		{
			P256.Current.GenerateKey(out byte[] privateKey, out byte[] verificationKey);
			return new SigningKey(verificationKey, privateKey);
		}

		/// <summary>Key pair from the stored private scalar; checks that it belongs to the verification key</summary>
		/// <exception cref="CryptographicException">The private key does not match the verification key</exception>
		public static SigningKey Import(byte[] privateKey, byte[] verificationKey)
		{
			var key = new SigningKey((byte[])verificationKey.Clone(), privateKey);
			try
			{
				if (!KeyWrap.IsKeyPair(privateKey, verificationKey))
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
			return P256.Current.SignData(privateKey, VerificationKey, data);
		}

		public static bool Verify(byte[] verificationKey, byte[] data, byte[] signature)
		{
			if (signature == null || signature.Length != SignatureLength) return false;
			try
			{
				return P256.Current.VerifyData(verificationKey, data, signature);
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
