using System;
using System.Runtime.InteropServices;

namespace KeePassPasskeyKeyProvider.WebAuthn
{
	/// <summary>
	/// P/Invoke wrapper для Windows WebAuthn API (webauthn.dll)
	/// Доступен в Windows 10 1903+ и Windows 11
	/// </summary>
	public static class WebAuthnApi
	{
		private const string DllName = "webauthn.dll";

		#region Константы

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

		// dwUsedTransport (CREDENTIAL_ATTESTATION v3+, ASSERTION v4+): каким транспортом ответил аутентификатор
		public const uint WEBAUTHN_CTAP_TRANSPORT_USB = 0x00000001;
		public const uint WEBAUTHN_CTAP_TRANSPORT_NFC = 0x00000002;
		public const uint WEBAUTHN_CTAP_TRANSPORT_BLE = 0x00000004;
		public const uint WEBAUTHN_CTAP_TRANSPORT_INTERNAL = 0x00000010;
		public const uint WEBAUTHN_CTAP_TRANSPORT_HYBRID = 0x00000020;

		// dwFlags для GET_ASSERTION_OPTIONS: передавать соли в hmac-secret «как есть»,
		// без PRF-преобразования SHA-256("WebAuthn PRF" || 0x00 || salt)
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

		#region Структуры

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
			// Поля для версии 5+
			public bool bBrowserInPrivateMode;
			// Поля для версии 6+
			public bool bEnablePrf;
			// Поля для версии 7+
			public IntPtr pLinkedDevice;
			public uint cbJsonExt;
			public IntPtr pbJsonExt;
			// Поля для версии 8+
			public IntPtr pPRFGlobalEval; // PWEBAUTHN_HMAC_SECRET_SALT — PRF eval при создании
			public uint cCredentialHints;
			public IntPtr ppwszCredentialHints;
			public bool bThirdPartyPayment;
			// Поля для версии 9+
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
			// Поля для версии 5+
			public uint dwCredLargeBlobOperation;
			public uint cbCredLargeBlob;
			public IntPtr pbCredLargeBlob;
			// Поля для версии 6+
			public IntPtr pHmacSecretSaltValues; // PWEBAUTHN_HMAC_SECRET_SALT_VALUES
			public bool bBrowserInPrivateMode;
			// Поля для версии 7+
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
		/// Входная структура для pHmacSecretSaltValues: глобальная соль и/или соли по credential ID
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
			// Версия 2+ (inline-структура, НЕ указатель!)
			public WEBAUTHN_EXTENSIONS Extensions;
			// Версия 3+
			public uint dwUsedTransport;
			// Версия 4+
			public bool bEpAtt;
			public bool bLargeBlobSupported;
			public bool bResidentKey;
			// Версия 5+
			public bool bPrfEnabled;
			// Версия 6+
			public uint cbUnsignedExtensionOutputs;
			public IntPtr pbUnsignedExtensionOutputs;
			// Версия 7+
			public IntPtr pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT — результат pPRFGlobalEval
			// Версия 8+
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
			// Версия 2+ (inline-структура, НЕ указатель!)
			public WEBAUTHN_EXTENSIONS Extensions;
			public uint cbCredLargeBlob;
			public IntPtr pbCredLargeBlob;
			public uint dwCredLargeBlobStatus;
			// Версия 3+
			public IntPtr pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT
			// Версия 4+
			public uint dwUsedTransport;
			// Версия 5+
			public uint cbUnsignedExtensionOutputs;
			public IntPtr pbUnsignedExtensionOutputs;
		}

		// ---- Список credential платформенного аутентификатора (Windows Hello), API 4+ ----

		public const uint WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1 = 1;

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_GET_CREDENTIALS_OPTIONS
		{
			public uint dwVersion;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string pwszRpId; // null — все RP
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
			// Версия 2+
			public bool bBackedUp;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct WEBAUTHN_CREDENTIAL_DETAILS_LIST
		{
			public uint cCredentialDetails;
			public IntPtr ppCredentialDetails; // массив указателей PWEBAUTHN_CREDENTIAL_DETAILS
		}

		#endregion

		#region Функции API

		/// <summary>
		/// Получает версию WebAuthn API
		/// </summary>
		[DllImport(DllName)]
		public static extern uint WebAuthNGetApiVersionNumber();

		/// <summary>
		/// Проверяет доступность пользовательской верификации на платформе
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
			[MarshalAs(UnmanagedType.Bool)] out bool pbIsUserVerifyingPlatformAuthenticatorAvailable);

		/// <summary>
		/// Создает новый credential на аутентификаторе
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
		/// Получает assertion от аутентификатора
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNAuthenticatorGetAssertion(
			IntPtr hWnd,
			[MarshalAs(UnmanagedType.LPWStr)] string pwszRpId,
			ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
			ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
			out IntPtr ppWebAuthNAssertion);

		/// <summary>
		/// Освобождает память, выделенную для credential attestation
		/// </summary>
		[DllImport(DllName)]
		public static extern void WebAuthNFreeCredentialAttestation(IntPtr pWebAuthNCredentialAttestation);

		/// <summary>
		/// Освобождает память, выделенную для assertion
		/// </summary>
		[DllImport(DllName)]
		public static extern void WebAuthNFreeAssertion(IntPtr pWebAuthNAssertion);

		/// <summary>
		/// Список discoverable credential Windows Hello (API 4+). NTE_NOT_FOUND, если пусто.
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNGetPlatformCredentialList(
			ref WEBAUTHN_GET_CREDENTIALS_OPTIONS pGetCredentialsOptions,
			out IntPtr ppCredentialDetailsList);

		[DllImport(DllName)]
		public static extern void WebAuthNFreePlatformCredentialList(IntPtr pCredentialDetailsList);

		/// <summary>
		/// Удаляет credential Windows Hello по ID (API 4+). Для credential на внешних ключах — ошибка.
		/// </summary>
		[DllImport(DllName)]
		public static extern int WebAuthNDeletePlatformCredential(uint cbCredentialId, byte[] pbCredentialId);

		/// <summary>
		/// Получает сообщение об ошибке
		/// </summary>
		// Возвращает статическую строку webauthn.dll: освобождать нельзя, поэтому IntPtr, а не string
		// (маршалинг в string вызывает CoTaskMemFree → порча кучи → аварийное завершение KeePass)
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

