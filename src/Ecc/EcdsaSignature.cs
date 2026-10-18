using System;
using System.Security.Cryptography;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>
	/// ECDSA P‑256 signature encodings: IEEE P1363 r ‖ s (used by the plugin) and DER SEQUENCE { INTEGER r, INTEGER s }
	/// (used by OpenSSL)
	/// </summary>
	internal static class EcdsaSignature
	{
		private const int IntegerLength = P256.PrivateKeyLength;

		public static byte[] ToDer(byte[] signature)
		{
			if (signature == null || signature.Length != P256.SignatureLength)
				throw new ArgumentException($"Expected {P256.SignatureLength} bytes of signature");

			byte[] r = EncodeInteger(signature, 0);
			byte[] s = EncodeInteger(signature, IntegerLength);
			byte[] der = new byte[2 + r.Length + s.Length];
			der[0] = 0x30;
			der[1] = (byte)(r.Length + s.Length);
			Array.Copy(r, 0, der, 2, r.Length);
			Array.Copy(s, 0, der, 2 + r.Length, s.Length);
			return der;
		}

		/// <exception cref="CryptographicException">Not a DER-encoded P‑256 signature</exception>
		public static byte[] FromDer(byte[] der)
		{
			// P‑256 integers fit in 33 bytes, so every length is in the short form
			if (der == null || der.Length < 2 || der[0] != 0x30 || der[1] != der.Length - 2)
				throw Malformed();

			byte[] signature = new byte[P256.SignatureLength];
			int position = 2;
			DecodeInteger(der, ref position, signature, 0);
			DecodeInteger(der, ref position, signature, IntegerLength);
			if (position != der.Length)
				throw Malformed();
			return signature;
		}

		/// <summary>Minimal unsigned big-endian INTEGER: no leading zeros except one before a set high bit</summary>
		private static byte[] EncodeInteger(byte[] signature, int offset)
		{
			int start = offset;
			int end = offset + IntegerLength;
			while (start < end - 1 && signature[start] == 0)
				start++;
			int padding = signature[start] >= 0x80 ? 1 : 0;
			int length = padding + end - start;

			byte[] result = new byte[2 + length];
			result[0] = 0x02;
			result[1] = (byte)length;
			Array.Copy(signature, start, result, 2 + padding, end - start);
			return result;
		}

		private static void DecodeInteger(byte[] der, ref int position, byte[] signature, int offset)
		{
			if (position + 2 > der.Length || der[position] != 0x02)
				throw Malformed();
			int length = der[position + 1];
			position += 2;
			if (length == 0 || position + length > der.Length)
				throw Malformed();

			int start = position;
			int count = length;
			while (count > IntegerLength && der[start] == 0)
			{
				start++;
				count--;
			}
			if (count > IntegerLength)
				throw Malformed();
			Array.Copy(der, start, signature, offset + IntegerLength - count, count);
			position += length;
		}

		private static CryptographicException Malformed()
		{
			return new CryptographicException("Malformed ECDSA signature");
		}
	}
}
