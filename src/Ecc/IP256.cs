namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>
	/// ECDH and ECDSA on P‑256 provided by the platform's crypto library (see <see cref="P256.Current"/>).
	/// Keys are raw: private scalar d (32 bytes) and public point 0x04 ‖ X ‖ Y. A public key that is not a point
	/// on the curve throws <see cref="System.Security.Cryptography.CryptographicException"/>.
	/// Whether d belongs to Q is not necessarily checked: callers use <see cref="KeyWrap.IsKeyPair"/>.
	/// Inputs are not modified; the caller wipes the private keys it passes and receives.
	/// </summary>
	internal interface IP256
	{
		/// <summary>New key pair</summary>
		void GenerateKey(out byte[] privateKey, out byte[] publicKey);

		/// <summary>SHA‑256(Z ‖ label), where Z is the ECDH shared secret (X coordinate of d·peer)</summary>
		byte[] DeriveKeyFromHash(byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] label);

		/// <summary>
		/// <see cref="DeriveKeyFromHash"/> with a fresh ephemeral key pair whose private key never leaves the crypto library
		/// </summary>
		byte[] DeriveEphemeralKeyFromHash(byte[] peerPublicKey, byte[] label, out byte[] ephemeralPublicKey);

		/// <summary>ECDSA signature over SHA‑256(data), IEEE P1363 r ‖ s</summary>
		byte[] SignData(byte[] privateKey, byte[] publicKey, byte[] data);

		/// <summary>Checks an ECDSA signature over SHA‑256(data) in IEEE P1363 format</summary>
		bool VerifyData(byte[] publicKey, byte[] data, byte[] signature);
	}
}
