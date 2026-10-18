using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using KeePassLib.Utility;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider.Fido2
{
	/// <summary>User interaction for <see cref="Fido2Authenticator.GetPrfSecret"/>, called on the thread of the request</summary>
	public interface IFido2Prompt
	{
		/// <summary>PIN of the key in UTF-8 without a terminator, or null to cancel; the array is zeroed after use</summary>
		/// <param name="device">Name of the key</param>
		/// <param name="retriesLeft">PIN attempts left before the key blocks the PIN; null if unknown</param>
		byte[] GetPin(string device, int? retriesLeft);

		/// <summary>A request is about to be sent: the key will wait for a touch (or a fingerprint)</summary>
		void TouchRequested(string device);
	}

	/// <summary>
	/// PRF secrets from FIDO2 security keys connected over USB, through libfido2 (Linux, macOS) instead of an OS WebAuthn API.
	/// hmac-secret with user verification (PIN or built-in) and the salt transformed as the WebAuthn PRF extension does,
	/// so the secret is the one Windows and browsers return for the same credential.
	/// Each connected key is first asked silently (no touch, no PIN) which credential of the allowList it holds: keys
	/// without one are skipped, and the request fits the key's limits on the allowList (number and length of IDs).
	/// The client data hash is random: the plugin does not verify assertions, it uses only the PRF secret.
	/// </summary>
	public static class Fido2Authenticator
	{
		private const int HashLength = 32; // SHA‑256: client data hash and hmac-secret output
		private const int MaxDevices = 64;

		// Commands that need no user (opening, GetInfo, silent requests) give up on a key that does not answer, so
		// the UI thread waiting for them is not blocked; the request that waits for the user has no timeout
		private const int QuickTimeoutMs = 5000;
		private const int NoTimeout = -1;

		private const string HmacSecretExtension = "hmac-secret";

		// CTAP PIN limits in UTF-8: at least 4 code points, at most 63 bytes. A shorter or longer PIN is rejected
		// here instead of spending an attempt on the key
		internal const int MinPinLength = 4;
		private const int MaxPinLength = 63;

		private static readonly byte[] PrfLabel = Encoding.ASCII.GetBytes("WebAuthn PRF\0");

		// Loaded on first use: a missing library must not break the type initialization
		private static readonly Lazy<LibFido2> library = new Lazy<LibFido2>(Load);

		/// <summary>libfido2 is installed (loads it on first use)</summary>
		public static bool IsAvailable
		{
			get
			{
				try
				{
					return library.Value != null;
				}
				catch (PlatformNotSupportedException)
				{
					return false;
				}
			}
		}

		/// <summary>
		/// PRF secret of a credential from <paramref name="allowList"/> on a connected security key. Blocks until the user
		/// touches the key; <paramref name="cancellation"/> cancels the request from another thread.
		/// </summary>
		/// <param name="rpId">RP ID of the credentials</param>
		/// <param name="allowList">IDs of the credentials that can open the database</param>
		/// <param name="prompt">Asks for the PIN and tells when the key waits for a touch</param>
		/// <param name="cancellation">Cancels the request</param>
		/// <returns>The credential (a copy of an allowList item) and its 32-byte PRF secret, which the caller zeroes</returns>
		/// <exception cref="Fido2Exception">No secret; <see cref="Fido2Exception.Error"/> tells why</exception>
		public static PrfResult GetPrfSecret(string rpId, IList<byte[]> allowList, IFido2Prompt prompt, CancellationToken cancellation)
		{
			if (string.IsNullOrEmpty(rpId))
				throw new ArgumentException("Empty RP ID", nameof(rpId));
			if (allowList == null || allowList.Count == 0 || UsableCredentials(allowList, 0).Count != allowList.Count)
				throw new ArgumentException("Empty allow list or credential ID", nameof(allowList));
			if (prompt == null)
				throw new ArgumentNullException(nameof(prompt));

			LibFido2 lib = Library;
			byte[] salt = HmacSecretSalt(WebAuthnHelper.PrfSalt);
			List<DeviceInfo> devices = Enumerate(lib);
			Log($"{devices.Count} device(s), RP ID \"{rpId}\", {allowList.Count} credential(s)");

			Fido2Exception skipped = null;
			foreach (DeviceInfo info in devices)
			{
				ThrowIfCancelled(cancellation);
				try
				{
					using (var device = new Device(lib, info))
						return device.GetPrfSecret(rpId, allowList, salt, prompt, cancellation);
				}
				catch (Fido2Exception ex) when (IsSkipped(ex.Error))
				{
					Log($"{info.Name}: skipped, {ex.Error}");
					// "No credential" means a usable key was asked: more useful than why other keys were not
					if (skipped == null || skipped.Error != Fido2Error.NoCredential)
						skipped = ex;
				}
			}
			throw skipped ?? new Fido2Exception(Fido2Error.NoDevice);
		}

		private static LibFido2 Library
		{
			get
			{
				try
				{
					return library.Value;
				}
				catch (PlatformNotSupportedException ex)
				{
					throw new Fido2Exception(Fido2Error.LibraryMissing, innerException: ex);
				}
			}
		}

		private static LibFido2 Load()
		{
			try
			{
				return new LibFido2();
			}
			catch (PlatformNotSupportedException ex)
			{
				Log(ex.Message);
				throw;
			}
		}

		/// <summary>hmac-secret salt for a PRF input, as the WebAuthn PRF extension computes it: SHA‑256("WebAuthn PRF" ‖ 0x00 ‖ input)</summary>
		internal static byte[] HmacSecretSalt(byte[] prfInput)
		{
			using (var sha = SHA256.Create())
			{
				sha.TransformBlock(PrfLabel, 0, PrfLabel.Length, null, 0);
				sha.TransformFinalBlock(prfInput, 0, prfInput.Length);
				return sha.Hash;
			}
		}

		/// <summary>Credential IDs a key accepts in the allowList: not empty and, if the key has a limit, not longer</summary>
		internal static List<byte[]> UsableCredentials(IList<byte[]> allowList, ulong maxLength)
		{
			var usable = new List<byte[]>();
			foreach (byte[] id in allowList)
				if (id != null && id.Length > 0 && (maxLength == 0 || (ulong)id.Length <= maxLength))
					usable.Add(id);
			return usable;
		}

		/// <summary>The allowList in parts of at most <paramref name="maxCount"/> IDs (0: no limit)</summary>
		internal static List<List<byte[]>> Batches(List<byte[]> credentials, ulong maxCount)
		{
			var batches = new List<List<byte[]>>();
			int size = maxCount == 0 || maxCount > int.MaxValue ? Math.Max(credentials.Count, 1) : (int)maxCount;
			for (int i = 0; i < credentials.Count; i += size)
				batches.Add(credentials.GetRange(i, Math.Min(size, credentials.Count - i)));
			return batches;
		}

		/// <summary>
		/// Copy of the sent credential the key answered with; null if it is not one of them. A key may omit the
		/// credential ID when the allowList has only one.
		/// </summary>
		internal static byte[] MatchCredential(byte[] answered, IList<byte[]> sent)
		{
			if (answered == null || answered.Length == 0)
				return sent.Count == 1 ? (byte[])sent[0].Clone() : null;
			foreach (byte[] id in sent)
				if (MemUtil.ArraysEqual(id, answered))
					return (byte[])id.Clone();
			return null;
		}

		/// <summary>Meaning of a libfido2 error code (fido/err.h) for the user</summary>
		internal static Fido2Error Classify(int code)
		{
			switch (code)
			{
				case LibFido2.FIDO_ERR_NO_CREDENTIALS:
					return Fido2Error.NoCredential;
				case LibFido2.FIDO_ERR_PIN_INVALID:
				case LibFido2.FIDO_ERR_PIN_POLICY_VIOLATION:
					return Fido2Error.PinInvalid;
				case LibFido2.FIDO_ERR_PIN_BLOCKED:
					return Fido2Error.PinBlocked;
				case LibFido2.FIDO_ERR_PIN_AUTH_BLOCKED:
					return Fido2Error.PinAuthBlocked;
				case LibFido2.FIDO_ERR_PIN_NOT_SET:
				case LibFido2.FIDO_ERR_PIN_REQUIRED:
					return Fido2Error.PinNotSet;
				case LibFido2.FIDO_ERR_UV_INVALID:
				case LibFido2.FIDO_ERR_UV_BLOCKED:
					return Fido2Error.UserVerificationFailed;
				case LibFido2.FIDO_ERR_USER_ACTION_TIMEOUT:
				case LibFido2.FIDO_ERR_ACTION_TIMEOUT:
					return Fido2Error.Timeout;
				case LibFido2.FIDO_ERR_KEEPALIVE_CANCEL:
				case LibFido2.FIDO_ERR_OPERATION_DENIED:
					return Fido2Error.Cancelled;
				case LibFido2.FIDO_ERR_UNSUPPORTED_EXTENSION:
				case LibFido2.FIDO_ERR_UNSUPPORTED_OPTION:
				case LibFido2.FIDO_ERR_INVALID_OPTION:
					return Fido2Error.Unsupported;
				default:
					return Fido2Error.DeviceError;
			}
		}

		/// <summary>Errors after which the next connected key is tried: this key cannot hold the credential</summary>
		internal static bool IsSkipped(Fido2Error error) =>
			error == Fido2Error.NoCredential || error == Fido2Error.Unsupported || error == Fido2Error.PinNotSet;

		private static List<DeviceInfo> Enumerate(LibFido2 lib)
		{
			IntPtr list = lib.fido_dev_info_new((UIntPtr)MaxDevices);
			if (list == IntPtr.Zero)
				throw new OutOfMemoryException();
			try
			{
				// Always FIDO_OK; a discovery error yields no devices
				lib.fido_dev_info_manifest(list, (UIntPtr)MaxDevices, out UIntPtr found);
				var devices = new List<DeviceInfo>();
				for (ulong i = 0; i < (ulong)found; i++)
				{
					IntPtr info = lib.fido_dev_info_ptr(list, (UIntPtr)i);
					string name = (Text(lib.fido_dev_info_manufacturer_string(info)) + " " +
						Text(lib.fido_dev_info_product_string(info))).Trim();
					string path = Text(lib.fido_dev_info_path(info));
					devices.Add(new DeviceInfo(path, name.Length > 0 ? name : path));
				}
				return devices;
			}
			finally
			{
				lib.fido_dev_info_free(ref list, (UIntPtr)MaxDevices);
			}
		}

		/// <summary>Name and code of a libfido2 result for messages</summary>
		private static string Describe(LibFido2 lib, int result) => $"{Text(lib.fido_strerr(result))} ({result})";

		/// <summary>C string owned by libfido2 (UTF-8: Mono decodes ANSI strings as UTF-8 outside Windows)</summary>
		private static string Text(IntPtr value) => value == IntPtr.Zero ? "" : Marshal.PtrToStringAnsi(value);

		private static void ThrowIfCancelled(CancellationToken cancellation)
		{
			if (cancellation.IsCancellationRequested)
				throw new Fido2Exception(Fido2Error.Cancelled);
		}

		private static void Log(string message) => WebAuthnHelper.Logger?.Invoke("[libfido2] " + message);

		private sealed class DeviceInfo
		{
			public DeviceInfo(string path, string name)
			{
				Path = path;
				Name = name;
			}

			public string Path { get; }

			public string Name { get; }
		}

		/// <summary>An open key</summary>
		private sealed class Device : IDisposable
		{
			private readonly LibFido2 lib;
			private readonly DeviceInfo info;
			private IntPtr handle;

			public Device(LibFido2 lib, DeviceInfo info)
			{
				this.lib = lib;
				this.info = info;
				handle = lib.fido_dev_new();
				if (handle == IntPtr.Zero)
					throw new OutOfMemoryException();
				SetTimeout(QuickTimeoutMs);
				int result = lib.fido_dev_open(handle, info.Path);
				if (result != LibFido2.FIDO_OK)
				{
					lib.fido_dev_free(ref handle);
					throw Error(result);
				}
			}

			public void Dispose()
			{
				if (handle == IntPtr.Zero)
					return;
				lib.fido_dev_close(handle);
				lib.fido_dev_free(ref handle);
			}

			public PrfResult GetPrfSecret(string rpId, IList<byte[]> allowList, byte[] salt, IFido2Prompt prompt,
				CancellationToken cancellation)
			{
				if (!lib.fido_dev_is_fido2(handle))
				{
					Log($"{info.Name} ({info.Path}): U2F only");
					throw new Fido2Exception(Fido2Error.Unsupported);
				}
				ReadInfo(out bool hmacSecret, out ulong maxIdLength, out ulong maxListLength);
				bool pin = lib.fido_dev_has_pin(handle);
				bool uv = lib.fido_dev_has_uv(handle);
				Log($"{info.Name} ({info.Path}): hmac-secret {hmacSecret}, PIN {pin}, built-in UV {uv}, " +
					$"credential ID up to {maxIdLength}, allowList up to {maxListLength} (0: no limit)");
				if (!hmacSecret)
					throw new Fido2Exception(Fido2Error.Unsupported);
				// hmac-secret gives a different secret without user verification
				if (!pin && !uv)
					throw new Fido2Exception(Fido2Error.PinNotSet);

				List<byte[]> usable = UsableCredentials(allowList, maxIdLength);
				byte[] found = FindCredential(rpId, usable, maxListLength);
				List<byte[]> request = found != null ? new List<byte[]> { found } : usable;

				if (uv)
				{
					int result = Request(rpId, request, salt, null, prompt, cancellation, out PrfResult secret);
					if (result == LibFido2.FIDO_OK)
						return secret;
					// Built-in verification blocked: the PIN still works
					if (!pin || (result != LibFido2.FIDO_ERR_UV_BLOCKED && result != LibFido2.FIDO_ERR_PIN_REQUIRED))
						throw Error(result, cancellation);
					Log($"{info.Name}: built-in user verification unavailable, asking for the PIN");
				}
				return RequestWithPin(rpId, request, salt, prompt, cancellation);
			}

			private PrfResult RequestWithPin(string rpId, IList<byte[]> request, byte[] salt, IFido2Prompt prompt,
				CancellationToken cancellation)
			{
				int? retries = PinRetries();
				byte[] pin = prompt.GetPin(info.Name, retries);
				if (pin == null)
					throw new Fido2Exception(Fido2Error.Cancelled);

				// NUL-terminated copy for libfido2
				byte[] terminated = new byte[pin.Length + 1];
				int result;
				try
				{
					if (pin.Length < MinPinLength || pin.Length > MaxPinLength)
						throw new Fido2Exception(Fido2Error.PinInvalid, retries);
					Array.Copy(pin, terminated, pin.Length);
					result = Request(rpId, request, salt, terminated, prompt, cancellation, out PrfResult secret);
					if (result == LibFido2.FIDO_OK)
						return secret;
				}
				finally
				{
					MemUtil.ZeroByteArray(pin);
					MemUtil.ZeroByteArray(terminated);
				}
				throw Error(result, cancellation);
			}

			/// <summary>
			/// Silent assertions (no user presence, no verification) with parts of the allowList: the credential this key
			/// holds; null if the key does not answer silent requests (in time)
			/// </summary>
			/// <exception cref="Fido2Exception">The key holds none of the credentials (<see cref="Fido2Error.NoCredential"/>)</exception>
			private byte[] FindCredential(string rpId, List<byte[]> usable, ulong maxListLength)
			{
				foreach (List<byte[]> batch in Batches(usable, maxListLength))
					using (var assert = new Assertion(lib, rpId, batch))
					{
						assert.Check(lib.fido_assert_set_up(assert.Handle, LibFido2.FIDO_OPT_FALSE));
						int result = lib.fido_dev_get_assert(handle, assert.Handle, null);
						if (result == LibFido2.FIDO_ERR_NO_CREDENTIALS)
							continue;
						byte[] found = result == LibFido2.FIDO_OK ? MatchCredential(assert.CredentialId(), batch) : null;
						Log(found != null ? $"{info.Name}: holds a credential of the allowList"
							: $"{info.Name}: no answer to a silent request ({Describe(lib, result)}), sending the whole allowList");
						return found;
					}
				throw new Fido2Exception(Fido2Error.NoCredential);
			}

			/// <summary>Assertion with hmac-secret and user verification: the PIN or, without it, built-in verification</summary>
			/// <returns>libfido2 result</returns>
			private int Request(string rpId, IList<byte[]> request, byte[] salt, byte[] pin, IFido2Prompt prompt,
				CancellationToken cancellation, out PrfResult secret)
			{
				secret = null;
				using (var assert = new Assertion(lib, rpId, request))
				{
					assert.Check(lib.fido_assert_set_extensions(assert.Handle, LibFido2.FIDO_EXT_HMAC_SECRET));
					assert.Check(lib.fido_assert_set_hmac_salt(assert.Handle, salt, (UIntPtr)salt.Length));
					// With a PIN libfido2 verifies the user through a PIN token and omits the uv option
					if (pin == null)
						assert.Check(lib.fido_assert_set_uv(assert.Handle, LibFido2.FIDO_OPT_TRUE));

					prompt.TouchRequested(info.Name);
					int result;
					SetTimeout(NoTimeout);
					try
					{
						// Dispose of the registration waits for a running cancel: the device is not closed under it
						using (cancellation.Register(() => lib.fido_dev_cancel(handle)))
						{
							ThrowIfCancelled(cancellation);
							result = lib.fido_dev_get_assert(handle, assert.Handle, pin);
						}
					}
					finally
					{
						SetTimeout(QuickTimeoutMs);
					}
					Log($"{info.Name}: assertion with {(pin != null ? "PIN" : "built-in UV")}: {Describe(lib, result)}");
					if (result != LibFido2.FIDO_OK)
						return result;

					byte[] credentialId = MatchCredential(assert.CredentialId(), request);
					if (credentialId == null)
						throw new Fido2Exception(Fido2Error.DeviceError, detail: "the key answered with another credential");
					byte[] prf = assert.HmacSecret();
					if (prf == null)
					{
						Log($"{info.Name}: no hmac-secret output");
						throw new Fido2Exception(Fido2Error.Unsupported);
					}
					secret = new PrfResult { CredentialId = credentialId, PrfSecret = prf };
					return result;
				}
			}

			/// <summary>Extensions and allowList limits from authenticatorGetInfo</summary>
			private void ReadInfo(out bool hmacSecret, out ulong maxIdLength, out ulong maxListLength)
			{
				IntPtr ci = lib.fido_cbor_info_new();
				if (ci == IntPtr.Zero)
					throw new OutOfMemoryException();
				try
				{
					int result = lib.fido_dev_get_cbor_info(handle, ci);
					if (result != LibFido2.FIDO_OK)
						throw Error(result);

					hmacSecret = false;
					IntPtr extensions = lib.fido_cbor_info_extensions_ptr(ci);
					ulong count = (ulong)lib.fido_cbor_info_extensions_len(ci);
					for (ulong i = 0; i < count && !hmacSecret; i++)
						hmacSecret = Text(Marshal.ReadIntPtr(extensions, (int)i * IntPtr.Size)) == HmacSecretExtension;
					maxIdLength = lib.fido_cbor_info_maxcredidlen(ci);
					maxListLength = lib.fido_cbor_info_maxcredcntlst(ci);
				}
				finally
				{
					lib.fido_cbor_info_free(ref ci);
				}
			}

			/// <summary>Timeout of the following commands (FIDO_ERR_RX when it expires); libfido2 before 1.9 waits without limit</summary>
			private void SetTimeout(int ms) => lib.fido_dev_set_timeout?.Invoke(handle, ms);

			/// <summary>PIN attempts left; null if the key does not tell</summary>
			private int? PinRetries() => lib.fido_dev_get_retry_count(handle, out int retries) == LibFido2.FIDO_OK ? retries : (int?)null;

			private Fido2Exception Error(int result, CancellationToken cancellation = default(CancellationToken))
			{
				// A cancelled request may end with an error other than FIDO_ERR_KEEPALIVE_CANCEL
				Fido2Error error = cancellation.IsCancellationRequested ? Fido2Error.Cancelled : Classify(result);
				return new Fido2Exception(error, error == Fido2Error.PinInvalid ? PinRetries() : null,
					error == Fido2Error.DeviceError ? Describe(lib, result) : null);
			}
		}

		/// <summary>An assertion request with a random client data hash and an allowList</summary>
		private sealed class Assertion : IDisposable
		{
			private readonly LibFido2 lib;
			private IntPtr handle;

			public Assertion(LibFido2 lib, string rpId, IList<byte[]> allowList)
			{
				this.lib = lib;
				handle = lib.fido_assert_new();
				if (handle == IntPtr.Zero)
					throw new OutOfMemoryException();
				try
				{
					byte[] clientDataHash = new byte[HashLength];
					using (var rng = new RNGCryptoServiceProvider())
						rng.GetBytes(clientDataHash);
					Check(lib.fido_assert_set_rp(handle, rpId));
					Check(lib.fido_assert_set_clientdata_hash(handle, clientDataHash, (UIntPtr)clientDataHash.Length));
					foreach (byte[] id in allowList)
						Check(lib.fido_assert_allow_cred(handle, id, (UIntPtr)id.Length));
				}
				catch
				{
					Dispose();
					throw;
				}
			}

			public IntPtr Handle => handle;

			public void Dispose() => lib.fido_assert_free(ref handle);

			/// <summary>Credential ID of the first statement; empty if the key omitted it</summary>
			public byte[] CredentialId() =>
				Copy(lib.fido_assert_id_ptr(handle, UIntPtr.Zero), lib.fido_assert_id_len(handle, UIntPtr.Zero));

			/// <summary>hmac-secret output of the first statement; null if the key did not return one</summary>
			public byte[] HmacSecret()
			{
				byte[] secret = Copy(lib.fido_assert_hmac_secret_ptr(handle, UIntPtr.Zero),
					lib.fido_assert_hmac_secret_len(handle, UIntPtr.Zero));
				if (secret.Length == HashLength)
					return secret;
				MemUtil.ZeroByteArray(secret);
				return null;
			}

			/// <exception cref="Fido2Exception">A setter failed (invalid argument or out of memory)</exception>
			public void Check(int result)
			{
				if (result != LibFido2.FIDO_OK)
					throw new Fido2Exception(Fido2Error.DeviceError, detail: Describe(lib, result));
			}

			private static byte[] Copy(IntPtr data, UIntPtr length)
			{
				// fido_assert_* return zero length when there is no statement
				byte[] bytes = new byte[data == IntPtr.Zero ? 0 : (int)length];
				if (bytes.Length > 0)
					Marshal.Copy(data, bytes, 0, bytes.Length);
				return bytes;
			}
		}
	}
}
