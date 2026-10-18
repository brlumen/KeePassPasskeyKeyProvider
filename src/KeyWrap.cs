using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeePassLib.Utility;
using KeePassPasskeyKeyProvider.Ecc;

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
		public const int PublicKeyLength = P256.PublicKeyLength;
		public const int SerializedLength = 2 * PublicKeyLength + 3 * KeyLength;

		// IMPORTANT: part of the database "format"
		private static readonly byte[] KdfLabel = Encoding.ASCII.GetBytes("KeePassPasskeyKeyProvider key wrap v1");
		private static readonly byte[] TagLabel = Encoding.ASCII.GetBytes("KeePassPasskeyKeyProvider owner tag v1");

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
			P256.Current.GenerateKey(out byte[] privateKey, out wrap.publicKey);
			try
			{
				wrap.encryptedPrivateKey = Xor(privateKey, secret);
			}
			finally
			{
				MemUtil.ZeroByteArray(privateKey);
			}

			wrap.Seal(key);
			return wrap;
		}

		/// <summary>Wraps a (new) database key for the same owner; the owner's secret is not needed, the tag is kept</summary>
		public void Seal(byte[] key)
		{
			CheckLength(key, KeyLength, "key");

			byte[] mask = P256.Current.DeriveEphemeralKeyFromHash(publicKey, KdfLabel, out byte[] ephemeral);
			try
			{
				wrappedKey = Xor(key, mask);
				ephemeralPublicKey = ephemeral;
			}
			finally
			{
				MemUtil.ZeroByteArray(mask);
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

			byte[] privateKey = Xor(encryptedPrivateKey, secret);
			try
			{
				// A wrong secret fails the tag check; a wrap whose parts were swapped under a copied tag fails here
				if (!IsKeyPair(privateKey, publicKey))
					throw new CryptographicException("The owner private key does not match the public key");
				byte[] mask = P256.Current.DeriveKeyFromHash(privateKey, publicKey, ephemeralPublicKey, KdfLabel);
				try
				{
					return Xor(wrappedKey, mask);
				}
				finally
				{
					MemUtil.ZeroByteArray(mask);
				}
			}
			finally
			{
				MemUtil.ZeroByteArray(privateKey);
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

		/// <summary>Wrap in the layout written by <see cref="Write"/></summary>
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

		/// <summary>
		/// Checks that the private scalar belongs to the public point: crypto libraries do not always check it on import
		/// (not every Windows version does), and a mismatched pair silently yields a wrong ECDH secret
		/// </summary>
		/// <exception cref="CryptographicException">The public key is not a point on the curve</exception>
		internal static bool IsKeyPair(byte[] privateKey, byte[] publicKey)
		{
			byte[] probe = new byte[KeyLength];
			byte[] signature = P256.Current.SignData(privateKey, publicKey, probe);
			return P256.Current.VerifyData(publicKey, probe, signature);
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
