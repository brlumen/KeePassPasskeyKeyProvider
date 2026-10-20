using System;
using System.Runtime.InteropServices;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider.Fido2
{
	/// <summary>Why <see cref="Fido2Authenticator"/> could not get a secret</summary>
	public enum Fido2Error
	{
		/// <summary>libfido2 is not installed or too old</summary>
		LibraryMissing,

		/// <summary>No FIDO2 security key is connected (on Linux also: the user has no access to it)</summary>
		NoDevice,

		/// <summary>No connected key holds a credential from the allowList</summary>
		NoCredential,

		/// <summary>The key did not answer (in time) a command that needs no user: it is skipped</summary>
		NoAnswer,

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

		/// <summary>
		/// The key does not accept a PIN now, most likely because of wrong PINs in a row (inferred from a libfido2 error,
		/// see <see cref="Fido2Authenticator.PinRefusal"/>)
		/// </summary>
		PinNotAccepted,

		/// <summary>Built-in user verification (fingerprint) failed</summary>
		UserVerificationFailed,

		/// <summary>The key was not touched in time</summary>
		Timeout,

		/// <summary>Cancelled by the caller, by the user in the PIN prompt or on the key</summary>
		Cancelled,

		/// <summary>Any other libfido2 or communication error (for example, the key was removed)</summary>
		DeviceError
	}

	/// <summary>FIDO2 security key error with a message for the user (in the KeePass UI language, no secrets)</summary>
	public sealed class Fido2Exception : WebAuthnException
	{
		private static readonly bool linux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

		/// <param name="detail">libfido2 error for <see cref="Fido2Error.DeviceError"/></param>
		public Fido2Exception(Fido2Error error, int? retriesLeft = null, string detail = null, Exception innerException = null)
			: base(Describe(error, retriesLeft, detail), innerException)
		{
			Error = error;
			RetriesLeft = retriesLeft;
		}

		public Fido2Error Error { get; }

		/// <summary>PIN attempts left; null if unknown</summary>
		public int? RetriesLeft { get; }

		/// <summary>No connected key holds a credential of the allowList: the user was not asked for anything</summary>
		public bool KeyNotFound => Error == Fido2Error.NoDevice || Fido2Authenticator.IsSkipped(Error);

		private static string Describe(Fido2Error error, int? retriesLeft, string detail)
		{
			switch (error)
			{
				case Fido2Error.LibraryMissing: return Strings.Fido2LibraryMissing;
				// On Linux a key without access rights is not listed at all
				case Fido2Error.NoDevice: return linux ? Strings.Fido2NoDevice + " " + Strings.Fido2AccessHint : Strings.Fido2NoDevice;
				case Fido2Error.NoCredential: return Strings.Fido2NoCredential;
				case Fido2Error.NoAnswer: return Strings.Fido2NoAnswer;
				case Fido2Error.Unsupported: return Strings.Fido2Unsupported;
				case Fido2Error.PinNotSet: return Strings.Fido2PinNotSet;
				case Fido2Error.PinInvalid:
					return retriesLeft == null ? Strings.PinWrong : Strings.PinWrong + " " + string.Format(Strings.PinAttemptsLeft, retriesLeft);
				case Fido2Error.PinBlocked: return Strings.Fido2PinBlocked;
				case Fido2Error.PinAuthBlocked: return Strings.Fido2PinAuthBlocked;
				case Fido2Error.PinNotAccepted: return Strings.Fido2PinNotAccepted;
				case Fido2Error.UserVerificationFailed: return Strings.Fido2UserVerificationFailed;
				case Fido2Error.Timeout: return Strings.Fido2Timeout;
				case Fido2Error.Cancelled: return Strings.OperationCancelled;
				default: return string.Format(Strings.Fido2DeviceError, detail);
			}
		}
	}
}
