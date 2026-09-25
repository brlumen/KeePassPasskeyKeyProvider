using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Database key K wrapped for one owner — a device or the recovery phrase (ECIES on P‑256).
	/// The owner has its own key pair (d, Q); d is stored as d ⊕ S, where S is the owner's 32-byte secret
	/// (device PRF or phrase secret R), so only the owner can recover d.
	/// K is encrypted to Q with a fresh ephemeral key e: K ⊕ SHA‑256(ECDH(e, Q) ‖ label).
	/// Re-wrapping for a new K (rotation) needs only Q, and wraps of different keys are unrelated:
	/// a revoked owner with old copies of the file learns nothing about the new K.
	/// </summary>
	public sealed class KeyWrap
	{
		public const int KeyLength = 32;
		private const int PublicKeyLength = 1 + 2 * KeyLength; // 0x04 ‖ X ‖ Y
		public const int SerializedLength = 2 * PublicKeyLength + 2 * KeyLength;

		// IMPORTANT: part of the database "format"
		private static readonly byte[] KdfLabel = Encoding.ASCII.GetBytes("KeePassPasskeyKeyProvider key wrap v1");
		private static readonly ECCurve Curve = ECCurve.NamedCurves.nistP256;

		private byte[] publicKey;
		private byte[] encryptedPrivateKey;
		private byte[] ephemeralPublicKey;
		private byte[] wrappedKey;

		private KeyWrap()
		{
		}

		/// <summary>New owner key pair protected by the owner's secret, with K wrapped for it</summary>
		public static KeyWrap Create(byte[] key, byte[] secret)
		{
			CheckLength(secret, KeyLength, "secret");

			var wrap = new KeyWrap();
			ECParameters owner;
			using (ECDiffieHellman ecdh = ECDiffieHellman.Create(Curve))
				owner = ecdh.ExportParameters(true);
			try
			{
				wrap.publicKey = EncodePoint(owner.Q);
				wrap.encryptedPrivateKey = Xor(owner.D, secret);
			}
			finally
			{
				MemUtil.ZeroByteArray(owner.D);
			}

			wrap.Seal(key);
			return wrap;
		}

		/// <summary>Wraps a (new) database key for the same owner; the owner's secret is not needed</summary>
		public void Seal(byte[] key)
		{
			CheckLength(key, KeyLength, "key");

			using (ECDiffieHellman ephemeral = ECDiffieHellman.Create(Curve))
			{
				byte[] mask = DeriveMask(ephemeral, publicKey);
				try
				{
					wrappedKey = Xor(key, mask);
					ephemeralPublicKey = EncodePoint(ephemeral.ExportParameters(false).Q);
				}
				finally
				{
					MemUtil.ZeroByteArray(mask);
				}
			}
		}

		/// <summary>Database key K from the owner's secret</summary>
		/// <exception cref="CryptographicException">The secret does not belong to this owner</exception>
		public byte[] Open(byte[] secret)
		{
			CheckLength(secret, KeyLength, "secret");

			var owner = new ECParameters { Curve = Curve, Q = DecodePoint(publicKey), D = Xor(encryptedPrivateKey, secret) };
			try
			{
				// Import checks that d matches Q: a wrong secret fails here
				using (ECDiffieHellman ecdh = ECDiffieHellman.Create(owner))
				{
					byte[] mask = DeriveMask(ecdh, ephemeralPublicKey);
					try
					{
						return Xor(wrappedKey, mask);
					}
					finally
					{
						MemUtil.ZeroByteArray(mask);
					}
				}
			}
			finally
			{
				MemUtil.ZeroByteArray(owner.D);
			}
		}

		public void Write(BinaryWriter bw)
		{
			bw.Write(publicKey);
			bw.Write(encryptedPrivateKey);
			bw.Write(ephemeralPublicKey);
			bw.Write(wrappedKey);
		}

		/// <exception cref="InvalidDataException">Truncated or malformed data</exception>
		public static KeyWrap Read(BinaryReader br)
		{
			var wrap = new KeyWrap
			{
				publicKey = ReadExact(br, PublicKeyLength),
				encryptedPrivateKey = ReadExact(br, KeyLength),
				ephemeralPublicKey = ReadExact(br, PublicKeyLength),
				wrappedKey = ReadExact(br, KeyLength)
			};
			if (wrap.publicKey[0] != 0x04 || wrap.ephemeralPublicKey[0] != 0x04)
				throw new InvalidDataException("Unsupported public key encoding");
			return wrap;
		}

		private static byte[] DeriveMask(ECDiffieHellman own, byte[] otherPublicKey)
		{
			var other = new ECParameters { Curve = Curve, Q = DecodePoint(otherPublicKey) };
			using (ECDiffieHellman peer = ECDiffieHellman.Create(other))
				return own.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256, null, KdfLabel);
		}

		private static byte[] EncodePoint(ECPoint q)
		{
			byte[] result = new byte[PublicKeyLength];
			result[0] = 0x04;
			Array.Copy(q.X, 0, result, 1, KeyLength);
			Array.Copy(q.Y, 0, result, 1 + KeyLength, KeyLength);
			return result;
		}

		private static ECPoint DecodePoint(byte[] data)
		{
			var q = new ECPoint { X = new byte[KeyLength], Y = new byte[KeyLength] };
			Array.Copy(data, 1, q.X, 0, KeyLength);
			Array.Copy(data, 1 + KeyLength, q.Y, 0, KeyLength);
			return q;
		}

		private static byte[] ReadExact(BinaryReader br, int length)
		{
			byte[] data = br.ReadBytes(length);
			if (data.Length != length) throw new EndOfStreamException();
			return data;
		}

		private static byte[] Xor(byte[] a, byte[] b)
		{
			CheckLength(a, KeyLength, "value");
			byte[] result = new byte[KeyLength];
			for (int i = 0; i < KeyLength; i++)
				result[i] = (byte)(a[i] ^ b[i]);
			return result;
		}

		private static void CheckLength(byte[] data, int length, string what)
		{
			if (data == null || data.Length != length)
				throw new ArgumentException($"Expected {length} bytes of {what}");
		}
	}
}
