using System;
using System.Runtime.InteropServices;

namespace KeePassPasskeyKeyProvider.WebAuthn
{
	/// <summary>
	/// P/Invoke wrapper for the Windows WebAuthn API (webauthn.dll)
	/// Available on Windows 10 1903+ and Windows 11
	/// </summary>
	public static class WebAuthnApi
	{
		private const string DllName = "webauthn.dll";

		#region Constants

		public const uint WEBAUTHN_API_VERSION_1 = 1;
		public const uint WEBAUTHN_API_VERSION_2 = 2;
		public const uint WEBAUTHN_API_VERSION_3 = 3;
		/// <summary>GET_ASSERTION_OPTIONS v6 (pHmacSecretSaltValues), ASSERTION v3 (pHmacSecret)</summary>
		public const uint WEBAUTHN_API_VERSION_4 = 4;
		/// <summary>MAKE_CREDENTIAL_OPTIONS v6 (bEnablePrf), CREDENTIAL_ATTESTATION v5 (bPrfEnabled)</summary>
		public const uint WEBAUTHN_API_VERSION_5 = 5;
		/// <summary>MAKE_CREDENTIAL_OPTIONS v8 (pPRFGlobalEval), CREDENTIAL_ATTESTATION v7 (pHmacSecret)</summary>
		public const uint WEBAUTHN_API_VERSION_8 = 8;

		public const uint WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5 = 5;
		public const uint WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6 = 6;
		public const uint WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8 = 8;
		public const uint WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6 = 6;
		public const uint WEBAUTHN_ASSERTION_VERSION_3 = 3;
		public const uint WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 = 3;
		public const uint WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5 = 5;
		public const uint WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7 = 7;

		// dwUsedTransport (CREDENTIAL_ATTESTATION v3+, ASSERTION v4+): transport the authenticator responded over
		public const uint WEBAUTHN_CTAP_TRANSPORT_USB = 0x00000001;
		public const uint WEBAUTHN_CTAP_TRANSPORT_NFC = 0x00000002;
		public const uint WEBAUTHN_CTAP_TRANSPORT_BLE = 0x00000004;
		public const uint WEBAUTHN_CTAP_TRANSPORT_INTERNAL = 0x00000010;
		public const uint WEBAUTHN_CTAP_TRANSPORT_HYBRID = 0x00000020;

		// dwFlags for GET_ASSERTION_OPTIONS: pass salts to hmac-secret as is,
		// without the PRF transform SHA-256("WebAuthn PRF" || 0x00 || salt)
		public const uint WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG = 0x00100000;

		public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
		public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
		public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
		public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2 = 3;

		public const uint WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY = 0;
		public const uint WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1;
		public const uint WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED = 2;
		public const uint WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;

		public const uint WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY = 0;
		public const uint WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1;
		public const uint WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 2;
		public const uint WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3;

		// COSE algorithm identifiers
		public const int WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 = -7;
		public const int WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384 = -35;
		public const int WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512 = -36;
		public const int WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256 = -257;
		public const int WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA384 = -258;
		public const int WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA512 = -259;
		public const int WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA256 = -37;
		public const int WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA384 = -38;
		public const int WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA512 = -39;

		// Credential Type
		public const string WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = "public-key";

		// Extension identifiers
		public const string WEBAUTHN_EXTENSIONS_IDENTIFIER_PRF = "prf";
		public const string WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET = "hmac-secret";

		#endregion

		#region Structures

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_RP_ENTITY_INFORMATION
		{
			public uint dwVersion;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszId;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszIcon;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_USER_ENTITY_INFORMATION
		{
			public uint dwVersion;
			public uint cbId;
			public IntPtr pbId;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszIcon;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszDisplayName;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER
		{
			public uint dwVersion;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszCredentialType;
			public int lAlg;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
		{
			public uint cCredentialParameters;
			public IntPtr pCredentialParameters;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CLIENT_DATA
		{
			public uint dwVersion;
			public uint cbClientDataJSON;
			public IntPtr pbClientDataJSON;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszHashAlgId;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CREDENTIAL
		{
			public uint dwVersion;
			public uint cbId;
			public IntPtr pbId;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszCredentialType;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CREDENTIALS
		{
			public uint cCredentials;
			public IntPtr pCredentials;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_EXTENSION
		{
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszExtensionIdentifier;
			public uint cbExtension;
			public IntPtr pvExtension;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_EXTENSIONS
		{
			public uint cExtensions;
			public IntPtr pExtensions;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
		{
			public uint dwVersion;
			public uint dwTimeoutMilliseconds;
			public WEBAUTHN_CREDENTIALS CredentialList;
			public WEBAUTHN_EXTENSIONS Extensions;
			public uint dwAuthenticatorAttachment;
			public bool bRequireResidentKey;
			public uint dwUserVerificationRequirement;
			public uint dwAttestationConveyancePreference;
			public uint dwFlags;
			public IntPtr pCancellationId;
			public IntPtr pExcludeCredentialList;
			public uint dwEnterpriseAttestation;
			public uint dwLargeBlobSupport;
			public bool bPreferResidentKey;
			// Fields for version 5+
			public bool bBrowserInPrivateMode;
			// Fields for version 6+
			public bool bEnablePrf;
			// Fields for version 7+
			public IntPtr pLinkedDevice;
			public uint cbJsonExt;
			public IntPtr pbJsonExt;
			// Fields for version 8+
			public IntPtr pPRFGlobalEval; // PWEBAUTHN_HMAC_SECRET_SALT — PRF eval at creation
			public uint cCredentialHints;
			public IntPtr ppwszCredentialHints;
			public bool bThirdPartyPayment;
			// Fields for version 9+
			public IntPtr pwszRemoteWebOrigin;
			public uint cbPublicKeyCredentialCreationOptionsJSON;
			public IntPtr pbPublicKeyCredentialCreationOptionsJSON;
			public uint cbAuthenticatorId;
			public IntPtr pbAuthenticatorId;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
		{
			public uint dwVersion;
			public uint dwTimeoutMilliseconds;
			public WEBAUTHN_CREDENTIALS CredentialList;
			public WEBAUTHN_EXTENSIONS Extensions;
			public uint dwAuthenticatorAttachment;
			public uint dwUserVerificationRequirement;
			public uint dwFlags;
			public IntPtr pwszU2fAppId;
			public IntPtr pbU2fAppId;
			public IntPtr pCancellationId;
			public IntPtr pAllowCredentialList;
			// Fields for version 5+
			public uint dwCredLargeBlobOperation;
			public uint cbCredLargeBlob;
			public IntPtr pbCredLargeBlob;
			// Fields for version 6+
			public IntPtr pHmacSecretSaltValues; // PWEBAUTHN_HMAC_SECRET_SALT_VALUES
			public bool bBrowserInPrivateMode;
			// Fields for version 7+
			public IntPtr pLinkedDevice;
			public bool bAutoFill;
			public uint cbJsonExt;
			public IntPtr pbJsonExt;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_HMAC_SECRET_SALT
		{
			public uint cbFirst;
			public IntPtr pbFirst;
			public uint cbSecond;
			public IntPtr pbSecond;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
		{
			public uint cbCredID;
			public IntPtr pbCredID;
			public IntPtr pHmacSecretSalt; // PWEBAUTHN_HMAC_SECRET_SALT
		}

		/// <summary>
		/// Input structure for pHmacSecretSaltValues: global salt and/or per-credential-ID salts
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_HMAC_SECRET_SALT_VALUES
		{
			public IntPtr pGlobalHmacSalt; // PWEBAUTHN_HMAC_SECRET_SALT
			public uint cCredWithHmacSecretSaltList;
			public IntPtr pCredWithHmacSecretSaltList; // PWEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CREDENTIAL_ATTESTATION
		{
			public uint dwVersion;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszFormatType;
			public uint cbAuthenticatorData;
			public IntPtr pbAuthenticatorData;
			public uint cbAttestation;
			public IntPtr pbAttestation;
			public uint dwAttestationDecodeType;
			public IntPtr pvAttestationDecode;
			public uint cbAttestationObject;
			public IntPtr pbAttestationObject;
			public uint cbCredentialId;
			public IntPtr pbCredentialId;
			// Version 2+ (inline structure, NOT a pointer!)
			public WEBAUTHN_EXTENSIONS Extensions;
			// Version 3+
			public uint dwUsedTransport;
			// Version 4+
			public bool bEpAtt;
			public bool bLargeBlobSupported;
			public bool bResidentKey;
			// Version 5+
			public bool bPrfEnabled;
			// Version 6+
			public uint cbUnsignedExtensionOutputs;
			public IntPtr pbUnsignedExtensionOutputs;
			// Version 7+
			public IntPtr pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT — result of pPRFGlobalEval
			// Version 8+
			public bool bThirdPartyPayment;
			public uint dwTransports;
			public uint cbClientDataJSON;
			public IntPtr pbClientDataJSON;
			public uint cbRegistrationResponseJSON;
			public IntPtr pbRegistrationResponseJSON;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_ASSERTION
		{
			public uint dwVersion;
			public uint cbAuthenticatorData;
			public IntPtr pbAuthenticatorData;
			public uint cbSignature;
			public IntPtr pbSignature;
			public WEBAUTHN_CREDENTIAL Credential;
			public uint cbUserId;
			public IntPtr pbUserId;
			// Version 2+ (inline structure, NOT a pointer!)
			public WEBAUTHN_EXTENSIONS Extensions;
			public uint cbCredLargeBlob;
			public IntPtr pbCredLargeBlob;
			public uint dwCredLargeBlobStatus;
			// Version 3+
			public IntPtr pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT
			// Version 4+
			public uint dwUsedTransport;
			// Version 5+
			public uint cbUnsignedExtensionOutputs;
			public IntPtr pbUnsignedExtensionOutputs;
		}

		// ---- Platform authenticator (Windows Hello) credential list, API 4+ ----

		public const uint WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1 = 1;

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_GET_CREDENTIALS_OPTIONS
		{
			public uint dwVersion;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszRpId; // null means all RPs
			public bool bBrowserInPrivateMode;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CREDENTIAL_DETAILS
		{
			public uint dwVersion;
			public uint cbCredentialID;
			public IntPtr pbCredentialID;
			public IntPtr pRpInformation;   // PWEBAUTHN_RP_ENTITY_INFORMATION
			public IntPtr pUserInformation; // PWEBAUTHN_USER_ENTITY_INFORMATION
			public bool bRemovable;
			// Version 2+
			public bool bBackedUp;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CREDENTIAL_DETAILS_LIST
		{
			public uint cCredentialDetails;
			public IntPtr ppCredentialDetails; // array of PWEBAUTHN_CREDENTIAL_DETAILS pointers
		}

		#endregion

		#region API functions

		/// <summary>
		/// Gets the WebAuthn API version
		/// </summary>
		[DllImport(DllName)]
		public static extern uint WebAuthNGetApiVersionNumber();

		/// <summary>
		/// Checks whether a user-verifying platform authenticator is available
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
			[MarshalAs(UnmanagedType.Bool)] out bool pbIsUserVerifyingPlatformAuthenticatorAvailable);

		/// <summary>
		/// Creates a new credential on the authenticator
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNAuthenticatorMakeCredential(
			IntPtr hWnd,
			ref WEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
			ref WEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
			ref WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pPubKeyCredParams,
			ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
			ref WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pWebAuthNMakeCredentialOptions,
			out IntPtr ppWebAuthNCredentialAttestation);

		/// <summary>
		/// Gets an assertion from the authenticator
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNAuthenticatorGetAssertion(
			IntPtr hWnd,
			[MarshalAs(UnmanagedType.LPWStr)] string pwszRpId,
			ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
			ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
			out IntPtr ppWebAuthNAssertion);

		/// <summary>
		/// Frees memory allocated for a credential attestation
		/// </summary>
		[DllImport(DllName)]
		public static extern void WebAuthNFreeCredentialAttestation(IntPtr pWebAuthNCredentialAttestation);

		/// <summary>
		/// Frees memory allocated for an assertion
		/// </summary>
		[DllImport(DllName)]
		public static extern void WebAuthNFreeAssertion(IntPtr pWebAuthNAssertion);

		/// <summary>
		/// Lists Windows Hello discoverable credentials (API 4+). NTE_NOT_FOUND if empty.
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNGetPlatformCredentialList(
			ref WEBAUTHN_GET_CREDENTIALS_OPTIONS pGetCredentialsOptions,
			out IntPtr ppCredentialDetailsList);

		[DllImport(DllName)]
		public static extern void WebAuthNFreePlatformCredentialList(IntPtr pCredentialDetailsList);

		/// <summary>
		/// Deletes a Windows Hello credential by ID (API 4+). Fails for credentials on external security keys.
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNDeletePlatformCredential(uint cbCredentialId, byte[] pbCredentialId);

		/// <summary>
		/// Gets the error message
		/// </summary>
		// Returns a static webauthn.dll string that must not be freed, hence IntPtr rather than string
		// (marshaling to string calls CoTaskMemFree → heap corruption → KeePass crash)
		[DllImport(DllName, EntryPoint = "WebAuthNGetErrorName")]
		private static extern IntPtr WebAuthNGetErrorNameRaw(int hr);

		public static string WebAuthNGetErrorName(int hr)
		{
			IntPtr p = WebAuthNGetErrorNameRaw(hr);
			return p == IntPtr.Zero ? "Unknown" : Marshal.PtrToStringUni(p);
		}

		#endregion
	}
}

