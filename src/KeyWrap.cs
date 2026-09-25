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
	/// Since anyone can wrap a key for Q, the wrap also carries the owner tag T = HMAC‑SHA256(S, label ‖ VK),
	/// computed when the wrap is created (the only moment S is available). It binds the owner to the database
	/// verification key VK (see <see cref="DeviceKeyStore"/>): a wrap copied into a forged database with a different
	/// VK is rejected by <see cref="Open"/>.
	/// </summary>
	public sealed class KeyWrap
	{
		public const int KeyLength = 32;
		public const int PublicKeyLength = 1 + 2 * KeyLength; // 0x04 ‖ X ‖ Y
		public const int SerializedLength = 2 * PublicKeyLength + 3 * KeyLength;

		// IMPORTANT: part of the database "format"
		private static readonly byte[] KdfLabel = Encoding.ASCII.GetBytes("KeePassPasskeyKeyProvider key wrap v1");
		private static readonly byte[] TagLabel = Encoding.ASCII.GetBytes("KeePassPasskeyKeyProvider owner tag v1");
		internal static readonly ECCurve Curve = ECCurve.NamedCurves.nistP256;

		private byte[] publicKey;
		private byte[] encryptedPrivateKey;
		private byte[] ephemeralPublicKey;
		private byte[] wrappedKey;
		private byte[] ownerTag;

		private KeyWrap()
		{
		}

		/// <summary>
		/// New owner key pair protected by the owner's secret, with K wrapped for it and the owner bound
		/// to the database verification key
		/// </summary>
		public static KeyWrap Create(byte[] key, byte[] secret, byte[] verificationKey)
		{
			CheckLength(secret, KeyLength, "secret");

			var wrap = new KeyWrap { ownerTag = ComputeTag(secret, verificationKey) };
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

		/// <summary>Wraps a (new) database key for the same owner; the owner's secret is not needed, the tag is kept</summary>
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

		/// <summary>Database key K from the owner's secret after checking the owner tag against the verification key</summary>
		/// <exception cref="CryptographicException">
		/// The secret does not belong to this owner, or the wrap was not created for this verification key
		/// </exception>
		public byte[] Open(byte[] secret, byte[] verificationKey)
		{
			CheckLength(secret, KeyLength, "secret");

			byte[] expectedTag = ComputeTag(secret, verificationKey);
			try
			{
				if (!FixedTimeEquals(expectedTag, ownerTag))
					throw new CryptographicException("Owner tag mismatch");
			}
			finally
			{
				MemUtil.ZeroByteArray(expectedTag);
			}

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
			bw.Write(ownerTag);
		}

		/// <exception cref="InvalidDataException">Truncated or malformed data</exception>
		public static KeyWrap Read(BinaryReader br)
		{
			var wrap = new KeyWrap
			{
				publicKey = ReadExact(br, PublicKeyLength),
				encryptedPrivateKey = ReadExact(br, KeyLength),
				ephemeralPublicKey = ReadExact(br, PublicKeyLength),
				wrappedKey = ReadExact(br, KeyLength),
				ownerTag = ReadExact(br, KeyLength)
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

		private static byte[] ComputeTag(byte[] secret, byte[] verificationKey)
		{
			CheckLength(verificationKey, PublicKeyLength, "verification key");
			using (var hmac = new HMACSHA256(secret))
			{
				hmac.TransformBlock(TagLabel, 0, TagLabel.Length, null, 0);
				hmac.TransformFinalBlock(verificationKey, 0, verificationKey.Length);
				return hmac.Hash;
			}
		}

		/// <summary>Comparison whose time does not depend on where the arrays differ</summary>
		internal static bool FixedTimeEquals(byte[] a, byte[] b)
		{
			if (a == null || b == null || a.Length != b.Length) return false;
			int diff = 0;
			for (int i = 0; i < a.Length; i++)
				diff |= a[i] ^ b[i];
			return diff == 0;
		}

		internal static byte[] EncodePoint(ECPoint q)
		{
			byte[] result = new byte[PublicKeyLength];
			result[0] = 0x04;
			Array.Copy(q.X, 0, result, 1, KeyLength);
			Array.Copy(q.Y, 0, result, 1 + KeyLength, KeyLength);
			return result;
		}

		internal static ECPoint DecodePoint(byte[] data)
		{
			CheckLength(data, PublicKeyLength, "public key");
			if (data[0] != 0x04) throw new CryptographicException("Unsupported public key encoding");
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
