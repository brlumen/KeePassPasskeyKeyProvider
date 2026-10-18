using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>P‑256 sizes and the implementation for the current OS</summary>
	internal static class P256
	{
		public const int PrivateKeyLength = 32;
		public const int PublicKeyLength = 1 + 2 * PrivateKeyLength; // 0x04 ‖ X ‖ Y
		public const int SignatureLength = 2 * PrivateKeyLength; // IEEE P1363: r ‖ s

		// Created on first use: a missing library must not break the type initialization
		private static readonly Lazy<IP256> current = new Lazy<IP256>(Create);

		/// <exception cref="PlatformNotSupportedException">The crypto library is missing (OpenSSL 3 outside Windows)</exception>
		public static IP256 Current => current.Value;

		private static IP256 Create()
		{
			// Mono has no ECC of its own: Windows has CNG, other systems OpenSSL
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return new CngP256();
			return new OpenSslP256();
		}

		/// <summary>Checks the encoding of a public key; whether the point is on the curve is checked on import</summary>
		/// <exception cref="CryptographicException">Not an uncompressed P‑256 point</exception>
		public static void CheckPublicKey(byte[] publicKey)
		{
			if (publicKey == null || publicKey.Length != PublicKeyLength || publicKey[0] != 0x04)
				throw new CryptographicException("Unsupported public key encoding");
		}
	}
}
