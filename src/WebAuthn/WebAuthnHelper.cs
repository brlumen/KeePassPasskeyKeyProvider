using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace KeePassPasskeyKeyProvider.WebAuthn
{
	/// <summary>
	/// High-level helper for the Windows WebAuthn API
	/// with hmac-secret/PRF extension support for deriving deterministic keys
	/// </summary>
	public static class WebAuthnHelper
	{
		// IMPORTANT: RP_ID and PRF_SALT are part of the key "format". Changing them makes existing databases unopenable!
		// Unique RP ID: with discoverable credentials an empty allowList shows ALL credentials for the RP,
		// and with "localhost" the list would include passkeys from local web development.
		private const string RP_ID = "keepass-fido2.local";
		public static string RpId => RP_ID;
		private const string RP_NAME = "KeePassPasskeyKeyProvider";
		private const uint TIMEOUT_MS = 120000; // 2 minutes: hybrid (phone) needs time for QR/BLE

		// Minimum API version: pHmacSecretSaltValues in GetAssertion (API 4 = Win10 22H2 / Win11)
		private const uint MIN_API_VERSION = WebAuthnApi.WEBAUTHN_API_VERSION_4;

		// PRF salt (32 bytes). Windows transforms it per the WebAuthn PRF spec:
		// hmac-secret salt = SHA-256("WebAuthn PRF" || 0x00 || PRF_SALT)
		private static readonly byte[] PRF_SALT =
		{
			0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46,
			0x49, 0x44, 0x4F, 0x32, 0x50, 0x52, 0x46, 0x53,
			0x61, 0x6C, 0x74, 0x76, 0x31, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		/// <summary>Logging delegate (the diagnostics form subscribes to it)</summary>
		public static Action<string> Logger { get; set; }

		private static void Log(string message) => Logger?.Invoke("[WebAuthn] " + message);

		private static string DumpBytes(IntPtr ptr, uint length, int maxLength = 64)
		{
			if (ptr == IntPtr.Zero || length == 0) return "(empty)";
			byte[] bytes = new byte[Math.Min((int)length, maxLength)];
			Marshal.Copy(ptr, bytes, 0, bytes.Length);
			string hex = BitConverter.ToString(bytes).Replace("-", " ");
			if (length > maxLength) hex += $"... ({length} bytes total)";
			return hex;
		}

		private static byte[] CopyBytes(IntPtr ptr, uint length)
		{
			byte[] result = new byte[length];
			Marshal.Copy(ptr, result, 0, (int)length);
			return result;
		}

		private static IntPtr AllocBytes(byte[] data)
		{
			IntPtr ptr = Marshal.AllocHGlobal(data.Length);
			Marshal.Copy(data, 0, ptr, data.Length);
			return ptr;
		}

		private static IntPtr AllocStruct<T>(T value) where T : struct
		{
			IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
			Marshal.StructureToPtr(value, ptr, false);
			return ptr;
		}

		/// <summary>
		/// Checks that the WebAuthn API of the required version is available
		/// </summary>
		public static bool IsWebAuthnAvailable()
		{
			return GetApiVersion() >= MIN_API_VERSION;
		}

		/// <summary>
		/// Gets the WebAuthn API version (0 if unavailable)
		/// </summary>
		public static uint GetApiVersion()
		{
			try
			{
				return WebAuthnApi.WebAuthNGetApiVersionNumber();
			}
			catch (DllNotFoundException) { return 0; }
			catch (EntryPointNotFoundException) { return 0; }
		}

		/// <summary>
		/// Creates a new credential with the hmac-secret/PRF extension.
		/// The credential is discoverable (resident): the key stores it itself, and on GetAssertion
		/// with an empty allowList the authenticator returns the credential ID in the response.
		/// </summary>
		/// <param name="userName">User/database name shown in Windows dialogs and on the phone</param>
		/// <param name="displayName">Full database path, used by cleanup to find orphaned credentials</param>
		/// <returns>Credential ID and, if API ≥ 8, the PRF secret right away (otherwise null)</returns>
		public static PrfResult CreateCredential(IntPtr windowHandle, byte[] userId, string userName, string displayName = null)
		{
			if (userId == null || userId.Length == 0)
				throw new ArgumentException("User ID cannot be null or empty", nameof(userId));
			if (string.IsNullOrWhiteSpace(userName))
				throw new ArgumentException("User name cannot be empty", nameof(userName));

			uint apiVersion = GetApiVersion();
			Log($"Creating credential: RP ID=\"{RP_ID}\", user=\"{userName}\", API v{apiVersion}, userId {userId.Length} bytes");

			IntPtr pUserId = IntPtr.Zero;
			IntPtr pClientDataJson = IntPtr.Zero;
			IntPtr pCredParam = IntPtr.Zero;
			IntPtr pHmacSecretFlag = IntPtr.Zero;
			IntPtr pExtension = IntPtr.Zero;
			IntPtr pSaltBytes = IntPtr.Zero;
			IntPtr pSalt = IntPtr.Zero;
			IntPtr pAttestation = IntPtr.Zero;

			try
			{
				pUserId = AllocBytes(userId);

				var rpInfo = new WebAuthnApi.WEBAUTHN_RP_ENTITY_INFORMATION
				{
					dwVersion = 1,
					pwszId = RP_ID,
					pwszName = RP_NAME
				};

				var userInfo = new WebAuthnApi.WEBAUTHN_USER_ENTITY_INFORMATION
				{
					dwVersion = 1,
					cbId = (uint)userId.Length,
					pbId = pUserId,
					pwszName = userName,
					pwszDisplayName = string.IsNullOrEmpty(displayName) ? userName : displayName
				};

				byte[] clientDataJson = Encoding.UTF8.GetBytes(CreateClientDataJson("webauthn.create"));
				pClientDataJson = AllocBytes(clientDataJson);
				var clientData = new WebAuthnApi.WEBAUTHN_CLIENT_DATA
				{
					dwVersion = 1,
					cbClientDataJSON = (uint)clientDataJson.Length,
					pbClientDataJSON = pClientDataJson,
					pwszHashAlgId = "SHA-256"
				};

				pCredParam = AllocStruct(new WebAuthnApi.WEBAUTHN_COSE_CREDENTIAL_PARAMETER
				{
					dwVersion = 1,
					pwszCredentialType = WebAuthnApi.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
					lAlg = WebAuthnApi.WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256
				});
				var credParams = new WebAuthnApi.WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
				{
					cCredentialParameters = 1,
					pCredentialParameters = pCredParam
				};

				// hmac-secret extension (BOOL TRUE) is the universal way to request hmac-secret at creation.
				// Additionally bEnablePrf (options v6, API 6+) for authenticators/transports with PRF semantics.
				pHmacSecretFlag = AllocStruct(1); // BOOL TRUE
				pExtension = AllocStruct(new WebAuthnApi.WEBAUTHN_EXTENSION
				{
					pwszExtensionIdentifier = WebAuthnApi.WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
					cbExtension = sizeof(int),
					pvExtension = pHmacSecretFlag
				});

				// API 8+: pPRFGlobalEval performs PRF eval right at creation (as Chrome 147+ does;
				// without it Windows Hello returns bPrfEnabled=false). The secret arrives in attestation.pHmacSecret.
				// Options version must be supported by the running API: v5 = API 4, v6 = API 6, v8 = API 8.
				bool usePrfFlag = apiVersion >= WebAuthnApi.WEBAUTHN_API_VERSION_6;
				bool usePrfEval = apiVersion >= WebAuthnApi.WEBAUTHN_API_VERSION_8;
				if (usePrfEval)
				{
					pSaltBytes = AllocBytes(PRF_SALT);
					pSalt = AllocStruct(new WebAuthnApi.WEBAUTHN_HMAC_SECRET_SALT
					{
						cbFirst = (uint)PRF_SALT.Length,
						pbFirst = pSaltBytes
					});
				}

				var options = new WebAuthnApi.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
				{
					dwVersion = usePrfEval ? WebAuthnApi.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8
						: usePrfFlag ? WebAuthnApi.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6
						: WebAuthnApi.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5,
					dwTimeoutMilliseconds = TIMEOUT_MS,
					Extensions = new WebAuthnApi.WEBAUTHN_EXTENSIONS { cExtensions = 1, pExtensions = pExtension },
					dwAuthenticatorAttachment = WebAuthnApi.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
					bRequireResidentKey = true,
					dwUserVerificationRequirement = WebAuthnApi.WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
					dwAttestationConveyancePreference = WebAuthnApi.WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
					bEnablePrf = usePrfFlag,
					pPRFGlobalEval = pSalt
				};

				Log($"MakeCredential: options v{options.dwVersion}, hmac-secret ext=true, bEnablePrf={usePrfFlag}, pPRFGlobalEval={usePrfEval}");
				IntPtr hWnd = PrepareOwnerWindow(windowHandle);
				IntPtr pResult = IntPtr.Zero;
				int hr = RunNativeCall(hWnd, () => WebAuthnApi.WebAuthNAuthenticatorMakeCredential(
					hWnd, ref rpInfo, ref userInfo, ref credParams, ref clientData, ref options, out pResult));
				pAttestation = pResult;

				if (hr != 0)
				{
					string errorName = WebAuthnApi.WebAuthNGetErrorName(hr);
					Log($"ERROR MakeCredential: {errorName} (HRESULT: 0x{hr:X8})");
					throw new WebAuthnException(string.Format(Strings.CreateCredentialFailed, errorName, hr));
				}

				var attestation = WebAuthnApi.ReadCredentialAttestation(pAttestation);
				Log($"MakeCredential OK: attestation v{attestation.dwVersion}, format={attestation.pwszFormatType}, " +
				    $"transport={attestation.dwUsedTransport}, credId {attestation.cbCredentialId} bytes");
				Log($"  Credential ID: {DumpBytes(attestation.pbCredentialId, attestation.cbCredentialId)}");

				if (attestation.cbCredentialId == 0 || attestation.pbCredentialId == IntPtr.Zero)
					throw new WebAuthnException("Credential ID is empty");

				// Verify that the authenticator actually enabled hmac-secret/PRF for the credential
				bool hmacSecretEnabled = ReadHmacSecretExtensionOutput(attestation.Extensions);
				bool prfEnabled = attestation.dwVersion >= WebAuthnApi.WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5 && attestation.bPrfEnabled;
				byte[] prfSecret = attestation.dwVersion >= WebAuthnApi.WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7
					? ReadHmacSecret(attestation.pHmacSecret)
					: null;
				Log($"  hmac-secret ext output: {hmacSecretEnabled}, bPrfEnabled: {prfEnabled}, " +
				    $"PRF secret at creation: {(prfSecret == null ? "none" : prfSecret.Length + " bytes")}");

				if (!hmacSecretEnabled && !prfEnabled && prfSecret == null)
				{
					Log("❌ Authenticator did NOT enable hmac-secret/PRF for the credential");
					throw new WebAuthnException(Strings.AuthenticatorNoPrf);
				}

				return new PrfResult
				{
					CredentialId = CopyBytes(attestation.pbCredentialId, attestation.cbCredentialId),
					PrfSecret = prfSecret,
					Transport = attestation.dwVersion >= WebAuthnApi.WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3
						? attestation.dwUsedTransport
						: 0
				};
			}
			finally
			{
				if (pAttestation != IntPtr.Zero) WebAuthnApi.WebAuthNFreeCredentialAttestation(pAttestation);
				if (pSalt != IntPtr.Zero) Marshal.FreeHGlobal(pSalt);
				if (pSaltBytes != IntPtr.Zero) Marshal.FreeHGlobal(pSaltBytes);
				if (pExtension != IntPtr.Zero) Marshal.FreeHGlobal(pExtension);
				if (pHmacSecretFlag != IntPtr.Zero) Marshal.FreeHGlobal(pHmacSecretFlag);
				if (pCredParam != IntPtr.Zero) Marshal.FreeHGlobal(pCredParam);
				if (pClientDataJson != IntPtr.Zero) Marshal.FreeHGlobal(pClientDataJson);
				if (pUserId != IntPtr.Zero) Marshal.FreeHGlobal(pUserId);
			}
		}

		/// <summary>
		/// Reads the first value from PWEBAUTHN_HMAC_SECRET_SALT (hmac-secret/PRF result); null if empty
		/// </summary>
		private static byte[] ReadHmacSecret(IntPtr pHmacSecret)
		{
			if (pHmacSecret == IntPtr.Zero) return null;
			var secret = Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_HMAC_SECRET_SALT>(pHmacSecret);
			Log($"  hmac-secret: cbFirst={secret.cbFirst}, cbSecond={secret.cbSecond}");
			if (secret.cbFirst == 0 || secret.pbFirst == IntPtr.Zero) return null;
			return CopyBytes(secret.pbFirst, secret.cbFirst);
		}

		/// <summary>
		/// Looks for "hmac-secret" with BOOL TRUE among the attestation output extensions
		/// </summary>
		private static bool ReadHmacSecretExtensionOutput(WebAuthnApi.WEBAUTHN_EXTENSIONS extensions)
		{
			int extSize = Marshal.SizeOf(typeof(WebAuthnApi.WEBAUTHN_EXTENSION));
			for (uint i = 0; i < extensions.cExtensions && extensions.pExtensions != IntPtr.Zero; i++)
			{
				var ext = Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_EXTENSION>(extensions.pExtensions + (int)(i * extSize));
				Log($"  ext[{i}]: {ext.pwszExtensionIdentifier}, {ext.cbExtension} bytes");
				if (ext.pwszExtensionIdentifier == WebAuthnApi.WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET
				    && ext.cbExtension >= sizeof(int) && ext.pvExtension != IntPtr.Zero)
				{
					return Marshal.ReadInt32(ext.pvExtension) != 0;
				}
			}
			return false;
		}

		/// <summary>
		/// Gets the PRF secret (32 bytes, deterministic) from the authenticator.
		/// </summary>
		/// <param name="allowList">Credential IDs the authenticator chooses from (Windows opens
		/// Hello directly if one of them is on this PC). null/empty means discoverable mode: the authenticator presents
		/// a credential for the RP itself; if there are several, Windows shows a picker</param>
		/// <returns>PRF secret and the credential ID it was obtained with</returns>
		public static PrfResult GetPrfSecret(IntPtr windowHandle, IList<byte[]> allowList = null)
		{
			bool discoverable = allowList == null || allowList.Count == 0;
			Log($"Getting hmac-secret: RP ID=\"{RP_ID}\", API v{GetApiVersion()}, " +
			    (discoverable ? "discoverable (allowList empty)" : $"allowList of {allowList.Count} credential(s)"));

			IntPtr pClientDataJson = IntPtr.Zero;
			var pCredentialIds = new List<IntPtr>();
			IntPtr pCredentials = IntPtr.Zero;
			IntPtr pSaltBytes = IntPtr.Zero;
			IntPtr pSalt = IntPtr.Zero;
			IntPtr pSaltValues = IntPtr.Zero;
			IntPtr pAssertion = IntPtr.Zero;

			try
			{
				byte[] clientDataJson = Encoding.UTF8.GetBytes(CreateClientDataJson("webauthn.get"));
				pClientDataJson = AllocBytes(clientDataJson);
				var clientData = new WebAuthnApi.WEBAUTHN_CLIENT_DATA
				{
					dwVersion = 1,
					cbClientDataJSON = (uint)clientDataJson.Length,
					pbClientDataJSON = pClientDataJson,
					pwszHashAlgId = "SHA-256"
				};

				// allowList is a contiguous WEBAUTHN_CREDENTIAL array
				var credentialList = new WebAuthnApi.WEBAUTHN_CREDENTIALS();
				if (!discoverable)
				{
					int credSize = Marshal.SizeOf(typeof(WebAuthnApi.WEBAUTHN_CREDENTIAL));
					pCredentials = Marshal.AllocHGlobal(credSize * allowList.Count);
					for (int i = 0; i < allowList.Count; i++)
					{
						IntPtr pId = AllocBytes(allowList[i]);
						pCredentialIds.Add(pId);
						Marshal.StructureToPtr(new WebAuthnApi.WEBAUTHN_CREDENTIAL
						{
							dwVersion = 1,
							cbId = (uint)allowList[i].Length,
							pbId = pId,
							pwszCredentialType = WebAuthnApi.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
						}, pCredentials + i * credSize, false);
					}
					credentialList = new WebAuthnApi.WEBAUTHN_CREDENTIALS
					{
						cCredentials = (uint)allowList.Count,
						pCredentials = pCredentials
					};
				}

				// Salt: WEBAUTHN_HMAC_SECRET_SALT_VALUES → pGlobalHmacSalt → WEBAUTHN_HMAC_SECRET_SALT → PRF_SALT
				pSaltBytes = AllocBytes(PRF_SALT);
				pSalt = AllocStruct(new WebAuthnApi.WEBAUTHN_HMAC_SECRET_SALT
				{
					cbFirst = (uint)PRF_SALT.Length,
					pbFirst = pSaltBytes
				});
				pSaltValues = AllocStruct(new WebAuthnApi.WEBAUTHN_HMAC_SECRET_SALT_VALUES
				{
					pGlobalHmacSalt = pSalt
				});

				// Options v6 (pHmacSecretSaltValues) came with API 4 = MIN_API_VERSION
				var options = new WebAuthnApi.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
				{
					dwVersion = WebAuthnApi.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
					dwTimeoutMilliseconds = TIMEOUT_MS,
					CredentialList = credentialList,
					dwAuthenticatorAttachment = WebAuthnApi.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
					dwUserVerificationRequirement = WebAuthnApi.WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
					pHmacSecretSaltValues = pSaltValues
				};

				Log($"GetAssertion: options v{options.dwVersion}, pHmacSecretSaltValues (global salt {PRF_SALT.Length} bytes)");
				IntPtr hWnd = PrepareOwnerWindow(windowHandle);
				IntPtr pResult = IntPtr.Zero;
				int hr = RunNativeCall(hWnd, () => WebAuthnApi.WebAuthNAuthenticatorGetAssertion(
					hWnd, RP_ID, ref clientData, ref options, out pResult));
				pAssertion = pResult;

				if (hr != 0)
				{
					string errorName = WebAuthnApi.WebAuthNGetErrorName(hr);
					Log($"ERROR GetAssertion: {errorName} (HRESULT: 0x{hr:X8})");
					throw new WebAuthnException(string.Format(Strings.GetAssertionFailed, errorName, hr));
				}

				var assertion = WebAuthnApi.ReadAssertion(pAssertion);
				Log($"GetAssertion OK: assertion v{assertion.dwVersion}, authData {assertion.cbAuthenticatorData} bytes, " +
				    $"credId {assertion.Credential.cbId} bytes, userId {assertion.cbUserId} bytes, " +
				    $"extensions={assertion.Extensions.cExtensions}, pHmacSecret=0x{assertion.pHmacSecret.ToString("X")}");

				if (assertion.dwVersion < WebAuthnApi.WEBAUTHN_ASSERTION_VERSION_3)
					throw new WebAuthnException($"Assertion v{assertion.dwVersion} has no pHmacSecret (v3+ required)");

				byte[] prfSecret = ReadHmacSecret(assertion.pHmacSecret);
				if (prfSecret == null)
				{
					Log("❌ Authenticator did not return hmac-secret");
					throw new WebAuthnException(Strings.HmacSecretNotReturned);
				}

				if (assertion.Credential.cbId == 0 || assertion.Credential.pbId == IntPtr.Zero)
					throw new WebAuthnException("Assertion has no credential ID");

				Log($"✓ hmac-secret received, {prfSecret.Length} bytes");
				return new PrfResult
				{
					CredentialId = CopyBytes(assertion.Credential.pbId, assertion.Credential.cbId),
					PrfSecret = prfSecret
				};
			}
			finally
			{
				if (pAssertion != IntPtr.Zero) WebAuthnApi.WebAuthNFreeAssertion(pAssertion);
				if (pSaltValues != IntPtr.Zero) Marshal.FreeHGlobal(pSaltValues);
				if (pSalt != IntPtr.Zero) Marshal.FreeHGlobal(pSalt);
				if (pSaltBytes != IntPtr.Zero) Marshal.FreeHGlobal(pSaltBytes);
				if (pCredentials != IntPtr.Zero)
				{
					int credSize = Marshal.SizeOf(typeof(WebAuthnApi.WEBAUTHN_CREDENTIAL));
					for (int i = 0; i < pCredentialIds.Count; i++)
						Marshal.DestroyStructure(pCredentials + i * credSize, typeof(WebAuthnApi.WEBAUTHN_CREDENTIAL));
					Marshal.FreeHGlobal(pCredentials);
				}
				foreach (IntPtr pId in pCredentialIds) Marshal.FreeHGlobal(pId);
				if (pClientDataJson != IntPtr.Zero) Marshal.FreeHGlobal(pClientDataJson);
			}
		}

		/// <summary>
		/// Device type name by transport (WEBAUTHN_CTAP_TRANSPORT_*), used as a label in the device list
		/// </summary>
		public static string TransportName(uint transport)
		{
			if ((transport & WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_INTERNAL) != 0) return "Windows Hello";
			if ((transport & WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_HYBRID) != 0) return Strings.TransportPhone;
			if ((transport & WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_USB) != 0) return Strings.TransportUsb;
			if ((transport & WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_NFC) != 0) return Strings.TransportNfc;
			if ((transport & WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_BLE) != 0) return Strings.TransportBluetooth;
			return Strings.TransportDefault;
		}

		/// <summary>
		/// Windows Hello discoverable credentials for our RP (API 4+). Empty list if there are none.
		/// </summary>
		public static List<PlatformCredential> ListPlatformCredentials()
		{
			var result = new List<PlatformCredential>();
			var options = new WebAuthnApi.WEBAUTHN_GET_CREDENTIALS_OPTIONS
			{
				dwVersion = WebAuthnApi.WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1,
				pwszRpId = RP_ID
			};

			IntPtr pList;
			int hr = WebAuthnApi.WebAuthNGetPlatformCredentialList(ref options, out pList);
			if (hr != 0)
			{
				Log($"GetPlatformCredentialList: {WebAuthnApi.WebAuthNGetErrorName(hr)} (0x{hr:X8})");
				return result; // NTE_NOT_FOUND: no credentials
			}

			try
			{
				var list = Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_CREDENTIAL_DETAILS_LIST>(pList);
				for (int i = 0; i < list.cCredentialDetails; i++)
				{
					IntPtr pDetails = Marshal.ReadIntPtr(list.ppCredentialDetails, i * IntPtr.Size);
					var details = WebAuthnApi.ReadCredentialDetails(pDetails);
					var user = details.pUserInformation == IntPtr.Zero
						? new WebAuthnApi.WEBAUTHN_USER_ENTITY_INFORMATION()
						: Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_USER_ENTITY_INFORMATION>(details.pUserInformation);

					result.Add(new PlatformCredential
					{
						CredentialId = CopyBytes(details.pbCredentialID, details.cbCredentialID),
						UserName = user.pwszName ?? string.Empty,
						DisplayName = user.pwszDisplayName ?? string.Empty
					});
				}
				Log($"GetPlatformCredentialList: {result.Count} credential(s) for {RP_ID}");
				return result;
			}
			finally
			{
				WebAuthnApi.WebAuthNFreePlatformCredentialList(pList);
			}
		}

		/// <summary>
		/// Deletes a Windows Hello credential. false if not found or not Hello (e.g. YubiKey or phone).
		/// </summary>
		public static bool DeletePlatformCredential(byte[] credentialId)
		{
			if (credentialId == null || credentialId.Length == 0) return false;
			int hr = WebAuthnApi.WebAuthNDeletePlatformCredential((uint)credentialId.Length, credentialId);
			Log($"DeletePlatformCredential({credentialId.Length} bytes): " +
			    (hr == 0 ? "OK" : $"{WebAuthnApi.WebAuthNGetErrorName(hr)} (0x{hr:X8})"));
			return hr == 0;
		}

		/// <summary>
		/// Creates the ClientData JSON with a random challenge
		/// </summary>
		private static string CreateClientDataJson(string type)
		{
			byte[] challenge = new byte[32];
			using (var rng = new RNGCryptoServiceProvider())
			{
				rng.GetBytes(challenge);
			}

			string challengeBase64 = Convert.ToBase64String(challenge)
				.TrimEnd('=')
				.Replace('+', '-')
				.Replace('/', '_');

			return $"{{\"type\":\"{type}\",\"challenge\":\"{challengeBase64}\",\"origin\":\"https://{RP_ID}\"}}";
		}

		/// <summary>
		/// Picks the owner window for the "Windows Security" dialog and brings it to the foreground.
		/// The WebAuthn dialog is z-ordered relative to hWnd: if the owner is inactive (or hWnd = 0),
		/// the dialog opens beneath the KeePass window.
		/// </summary>
		private static IntPtr PrepareOwnerWindow(IntPtr windowHandle)
		{
			IntPtr foreground = User32.GetForegroundWindow();
			uint currentProcess = User32.GetCurrentProcessId();

			// No owner, or it is minimized or hidden (tray): use our process's active window, if any
			if (windowHandle == IntPtr.Zero || User32.IsIconic(windowHandle) || !User32.IsWindowVisible(windowHandle))
			{
				if (foreground != IntPtr.Zero && GetWindowProcessId(foreground) == currentProcess)
				{
					windowHandle = foreground;
				}
			}

			if (windowHandle == IntPtr.Zero)
			{
				Log("Owner window not determined, the WebAuthn dialog will have no owner");
				return windowHandle;
			}

			if (foreground != windowHandle)
			{
				bool ok = User32.SetForegroundWindow(windowHandle);
				Log($"SetForegroundWindow(0x{windowHandle.ToInt64():X}) = {ok}");
			}

			return windowHandle;
		}

		/// <summary>
		/// Runs the blocking webauthn.dll call on a separate thread while the UI thread keeps
		/// pumping messages. Otherwise the KeePass window becomes "Not Responding", Windows
		/// replaces it with a ghost window and the "Windows Security" dialog ends up beneath it.
		/// The owner window is disabled for the duration of the call (as with a modal dialog).
		/// </summary>
		private static int RunNativeCall(IntPtr ownerHandle, Func<int> nativeCall)
		{
			if (!Application.MessageLoop)
				return nativeCall();

			int hr = 0;
			Exception error = null;
			var thread = new Thread(() =>
			{
				try { hr = nativeCall(); }
				catch (Exception ex) { error = ex; }
			})
			{
				IsBackground = true,
				Name = "WebAuthn"
			};

			bool ownerWasEnabled = ownerHandle != IntPtr.Zero && User32.IsWindowEnabled(ownerHandle);
			if (ownerWasEnabled) User32.EnableWindow(ownerHandle, false);
			try
			{
				// The "Windows Security" dialog is drawn by another process (the broker). While KeePass is the foreground process,
				// the broker may not take focus and its window ends up beneath KeePass. Allow it explicitly.
				User32.AllowSetForegroundWindow(User32.ASFW_ANY);

				thread.Start();
				bool dialogRaised = false;
				while (!thread.Join(50))
				{
					Application.DoEvents();
					if (!dialogRaised)
						dialogRaised = RaiseSecurityDialog();
				}
			}
			finally
			{
				if (ownerWasEnabled) User32.EnableWindow(ownerHandle, true);
			}

			if (error != null)
				throw new WebAuthnException("WebAuthn API call failed", error);
			return hr;
		}

		/// <summary>
		/// Fallback: finds the "Windows Security" window and brings it to the foreground (once).
		/// </summary>
		private static bool RaiseSecurityDialog()
		{
			IntPtr dialog = User32.FindWindow(SECURITY_DIALOG_CLASS, null);
			if (dialog == IntPtr.Zero || !User32.IsWindowVisible(dialog))
				return false;

			if (User32.GetForegroundWindow() != dialog)
			{
				bool ok = User32.SetForegroundWindow(dialog);
				Log($"\"Windows Security\" dialog 0x{dialog.ToInt64():X} brought to foreground: {ok}");
			}
			return true;
		}

		// Window class of the "Windows Security" dialog (Windows Hello / WebAuthn)
		private const string SECURITY_DIALOG_CLASS = "Credential Dialog Xaml Host";

		private static uint GetWindowProcessId(IntPtr hWnd)
		{
			uint pid;
			User32.GetWindowThreadProcessId(hWnd, out pid);
			return pid;
		}

		private static class User32
		{
			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			public static extern IntPtr GetForegroundWindow();

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool SetForegroundWindow(IntPtr hWnd);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool IsIconic(IntPtr hWnd);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool IsWindowVisible(IntPtr hWnd);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool IsWindowEnabled(IntPtr hWnd);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool EnableWindow(IntPtr hWnd, [MarshalAs(UnmanagedType.Bool)] bool bEnable);

			public const int ASFW_ANY = -1;

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool AllowSetForegroundWindow(int dwProcessId);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll", CharSet = CharSet.Unicode)]
			public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("user32.dll")]
			public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

			[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
			[DllImport("kernel32.dll")]
			public static extern uint GetCurrentProcessId();
		}
	}

	/// <summary>
	/// MakeCredential / GetAssertion result: credential ID and PRF secret
	/// </summary>
	public class PrfResult
	{
		public byte[] CredentialId { get; set; }

		/// <summary>PRF secret (32 bytes). null at creation on API &lt; 8, then GetPrfSecret is needed</summary>
		public byte[] PrfSecret { get; set; }

		/// <summary>Authenticator transport (WEBAUTHN_CTAP_TRANSPORT_*); 0 if unknown</summary>
		public uint Transport { get; set; }
	}

	/// <summary>
	/// Windows Hello credential from WebAuthNGetPlatformCredentialList
	/// </summary>
	public class PlatformCredential
	{
		public byte[] CredentialId { get; set; }
		public string UserName { get; set; }
		/// <summary>Full database path (plugin credential) or user name</summary>
		public string DisplayName { get; set; }
	}

	/// <summary>
	/// Exception for WebAuthn errors
	/// </summary>
	public class WebAuthnException : Exception
	{
		public WebAuthnException(string message) : base(message)
		{
		}

		public WebAuthnException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}
