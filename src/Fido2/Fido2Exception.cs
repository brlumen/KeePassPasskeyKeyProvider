using System;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider.Fido2
{
	/// <summary>Why <see cref="Fido2Authenticator"/> could not get a secret</summary>
	public enum Fido2Error
	{
		/// <summary>libfido2 is not installed or too old</summary>
		LibraryMissing,

		/// <summary>No FIDO2 security key is connected (on Linux also: no access to it, see the udev rules of libfido2)</summary>
		NoDevice,

		/// <summary>No connected key holds a credential from the allowList</summary>
		NoCredential,

		/// <summary>The key cannot be used: U2F only, no hmac-secret, or it rejected the request options</summary>
		Unsupported,

		/// <summary>The key can verify the user neither with a PIN nor with a built-in method</summary>
		PinNotSet,

		/// <summary>Wrong PIN; <see cref="Fido2Exception.RetriesLeft"/> attempts left</summary>
		PinInvalid,

		/// <summary>No PIN attempts left: the key must be reset</summary>
		PinBlocked,

		/// <summary>Too many wrong PINs in a row: the key must be reinserted</summary>
		PinAuthBlocked,

		/// <summary>Built-in user verification (fingerprint) failed</summary>
		UserVerificationFailed,

		/// <summary>The key was not touched in time</summary>
		Timeout,

		/// <summary>Cancelled by the caller, by the user in the PIN prompt or on the key</summary>
		Cancelled,

		/// <summary>Any other libfido2 or communication error (for example, the key was removed)</summary>
		DeviceError
	}

	/// <summary>FIDO2 security key error; the message is English and holds no secrets</summary>
	public sealed class Fido2Exception : WebAuthnException
	{
		/// <param name="detail">Appended to the message of the error, for example the libfido2 error</param>
		public Fido2Exception(Fido2Error error, int? retriesLeft = null, string detail = null, Exception innerException = null)
			: base(Describe(error, retriesLeft, detail), innerException)
		{
			Error = error;
			RetriesLeft = retriesLeft;
		}

		public Fido2Error Error { get; }

		/// <summary>PIN attempts left; null if unknown</summary>
		public int? RetriesLeft { get; }

		private static string Describe(Fido2Error error, int? retriesLeft, string detail)
		{
			string message = DefaultMessage(error);
			if (retriesLeft != null)
				message += $" ({retriesLeft} attempts left)";
			return detail == null ? message : message + ": " + detail;
		}

		private static string DefaultMessage(Fido2Error error)
		{
			switch (error)
			{
				case Fido2Error.LibraryMissing: return "libfido2 is not available";
				case Fido2Error.NoDevice: return "No FIDO2 security key is connected";
				case Fido2Error.NoCredential: return "No connected security key holds a credential of this database";
				case Fido2Error.Unsupported: return "The security key does not support FIDO2 hmac-secret";
				case Fido2Error.PinNotSet: return "The security key has no PIN and no built-in user verification";
				case Fido2Error.PinInvalid: return "Wrong PIN";
				case Fido2Error.PinBlocked: return "The PIN is blocked after too many wrong attempts";
				case Fido2Error.PinAuthBlocked: return "Too many wrong PINs in a row: remove and reinsert the security key";
				case Fido2Error.UserVerificationFailed: return "User verification failed";
				case Fido2Error.Timeout: return "The security key was not touched in time";
				case Fido2Error.Cancelled: return "Cancelled";
				default: return "Security key error";
			}
		}
	}
}
