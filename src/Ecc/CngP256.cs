using System;
using System.Security.Cryptography;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>P‑256 on Windows: .NET Framework over CNG</summary>
	internal sealed class CngP256 : IP256
	{
		private static readonly ECCurve Curve = ECCurve.NamedCurves.nistP256;

		public void GenerateKey(out byte[] privateKey, out byte[] publicKey)
		{
			using (ECDiffieHellman ecdh = ECDiffieHellman.Create(Curve))
			{
				ECParameters p = ecdh.ExportParameters(true);
				privateKey = p.D;
				publicKey = EncodePoint(p.Q);
			}
		}

		public byte[] DeriveKeyFromHash(byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] label)
		{
			var own = new ECParameters { Curve = Curve, Q = DecodePoint(publicKey), D = privateKey };
			using (ECDiffieHellman ecdh = Import(() => ECDiffieHellman.Create(own)))
				return DeriveKeyFromHash(ecdh, peerPublicKey, label);
		}

		public byte[] DeriveEphemeralKeyFromHash(byte[] peerPublicKey, byte[] label, out byte[] ephemeralPublicKey)
		{
			using (ECDiffieHellman ephemeral = ECDiffieHellman.Create(Curve))
			{
				byte[] key = DeriveKeyFromHash(ephemeral, peerPublicKey, label);
				ephemeralPublicKey = EncodePoint(ephemeral.ExportParameters(false).Q);
				return key;
			}
		}

		public byte[] SignData(byte[] privateKey, byte[] publicKey, byte[] data)
		{
			var p = new ECParameters { Curve = Curve, Q = DecodePoint(publicKey), D = privateKey };
			using (ECDsa ecdsa = Import(() => ECDsa.Create(p)))
				return ecdsa.SignData(data, HashAlgorithmName.SHA256);
		}

		public bool VerifyData(byte[] publicKey, byte[] data, byte[] signature)
		{
			var p = new ECParameters { Curve = Curve, Q = DecodePoint(publicKey) };
			using (ECDsa ecdsa = Import(() => ECDsa.Create(p)))
				return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
		}

		private static byte[] DeriveKeyFromHash(ECDiffieHellman own, byte[] peerPublicKey, byte[] label)
		{
			var other = new ECParameters { Curve = Curve, Q = DecodePoint(peerPublicKey) };
			using (ECDiffieHellman peer = Import(() => ECDiffieHellman.Create(other)))
				return own.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256, null, label);
		}

		/// <summary>
		/// Key from imported parameters. .NET Framework reports a point off the curve as PlatformNotSupportedException;
		/// callers expect CryptographicException for any invalid key material.
		/// </summary>
		private static T Import<T>(Func<T> create)
		{
			try
			{
				return create();
			}
			catch (PlatformNotSupportedException ex)
			{
				throw new CryptographicException("Invalid elliptic curve key", ex);
			}
		}

		private static byte[] EncodePoint(ECPoint q)
		{
			byte[] result = new byte[P256.PublicKeyLength];
			result[0] = 0x04;
			Array.Copy(q.X, 0, result, 1, P256.PrivateKeyLength);
			Array.Copy(q.Y, 0, result, 1 + P256.PrivateKeyLength, P256.PrivateKeyLength);
			return result;
		}

		private static ECPoint DecodePoint(byte[] data)
		{
			P256.CheckPublicKey(data);
			var q = new ECPoint { X = new byte[P256.PrivateKeyLength], Y = new byte[P256.PrivateKeyLength] };
			Array.Copy(data, 1, q.X, 0, P256.PrivateKeyLength);
			Array.Copy(data, 1 + P256.PrivateKeyLength, q.Y, 0, P256.PrivateKeyLength);
			return q;
		}
	}
}
