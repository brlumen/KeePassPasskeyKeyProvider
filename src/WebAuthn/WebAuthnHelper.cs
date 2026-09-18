using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KeePassFIDO2.WebAuthn
{
	/// <summary>
	/// Высокоуровневый helper для работы с Windows WebAuthn API
	/// с поддержкой hmac-secret/PRF extension для генерации детерминированных ключей
	/// </summary>
	public static class WebAuthnHelper
	{
		// ВАЖНО: RP_ID и PRF_SALT — часть «формата» ключа. Их изменение сделает существующие базы неоткрываемыми!
		private const string RP_ID = "localhost";
		private const string RP_NAME = "KeePass FIDO2 Plugin";
		private const uint TIMEOUT_MS = 120000; // 2 минуты — hybrid (телефон) требует времени на QR/BLE

		// Минимальная версия API: pHmacSecretSaltValues в GetAssertion (API 4 = Win10 22H2 / Win11)
		private const uint MIN_API_VERSION = WebAuthnApi.WEBAUTHN_API_VERSION_4;

		// Соль для PRF (32 байта). Windows преобразует её по спецификации WebAuthn PRF:
		// hmac-secret salt = SHA-256("WebAuthn PRF" || 0x00 || PRF_SALT)
		private static readonly byte[] PRF_SALT =
		{
			0x4B, 0x65, 0x65, 0x50, 0x61, 0x73, 0x73, 0x46,
			0x49, 0x44, 0x4F, 0x32, 0x50, 0x52, 0x46, 0x53,
			0x61, 0x6C, 0x74, 0x76, 0x31, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		/// <summary>Делегат для логирования (диагностическая форма подписывается на него)</summary>
		public static Action<string> Logger { get; set; }

		private static void Log(string message) => Logger?.Invoke("[WebAuthn] " + message);

		private static string DumpBytes(IntPtr ptr, uint length, int maxLength = 64)
		{
			if (ptr == IntPtr.Zero || length == 0) return "(empty)";
			byte[] bytes = new byte[Math.Min((int)length, maxLength)];
			Marshal.Copy(ptr, bytes, 0, bytes.Length);
			string hex = BitConverter.ToString(bytes).Replace("-", " ");
			if (length > maxLength) hex += $"... ({length} байт всего)";
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
		/// Проверяет доступность WebAuthn API нужной версии
		/// </summary>
		public static bool IsWebAuthnAvailable()
		{
			return GetApiVersion() >= MIN_API_VERSION;
		}

		/// <summary>
		/// Получает версию WebAuthn API (0 — недоступен)
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
		/// Создает новый credential с hmac-secret/PRF extension.
		/// </summary>
		/// <param name="userName">Имя пользователя/базы — показывается в диалогах Windows и на телефоне</param>
		/// <returns>Credential ID (нужно сохранить) и, если API ≥ 8, сразу PRF-секрет (иначе null)</returns>
		public static CredentialCreationResult CreateCredential(IntPtr windowHandle, byte[] userId, string userName)
		{
			if (userId == null || userId.Length == 0)
				throw new ArgumentException("User ID cannot be null or empty", nameof(userId));
			if (string.IsNullOrWhiteSpace(userName))
				throw new ArgumentException("User name cannot be empty", nameof(userName));

			uint apiVersion = GetApiVersion();
			Log($"Создание credential: RP ID=\"{RP_ID}\", user=\"{userName}\", API v{apiVersion}, userId {userId.Length} байт");

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
					pwszDisplayName = userName
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

				// Расширение hmac-secret (BOOL TRUE) — универсальный способ запросить hmac-secret при создании.
				// Дополнительно bEnablePrf (options v6, API 5+) — для аутентификаторов/транспортов с PRF-семантикой.
				pHmacSecretFlag = AllocStruct(1); // BOOL TRUE
				pExtension = AllocStruct(new WebAuthnApi.WEBAUTHN_EXTENSION
				{
					pwszExtensionIdentifier = WebAuthnApi.WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
					cbExtension = sizeof(int),
					pvExtension = pHmacSecretFlag
				});

				// API 8+: pPRFGlobalEval — PRF eval прямо при создании (так делает Chrome 147+;
				// без него Windows Hello возвращает bPrfEnabled=false). Секрет приходит в attestation.pHmacSecret.
				bool usePrfFlag = apiVersion >= WebAuthnApi.WEBAUTHN_API_VERSION_5;
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
					bRequireResidentKey = false,
					dwUserVerificationRequirement = WebAuthnApi.WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
					dwAttestationConveyancePreference = WebAuthnApi.WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
					bEnablePrf = usePrfFlag,
					pPRFGlobalEval = pSalt
				};

				Log($"MakeCredential: options v{options.dwVersion}, hmac-secret ext=true, bEnablePrf={usePrfFlag}, pPRFGlobalEval={usePrfEval}");
				int hr = WebAuthnApi.WebAuthNAuthenticatorMakeCredential(
					windowHandle, ref rpInfo, ref userInfo, ref credParams, ref clientData, ref options, out pAttestation);

				if (hr != 0)
				{
					string errorName = WebAuthnApi.WebAuthNGetErrorName(hr);
					Log($"ОШИБКА MakeCredential: {errorName} (HRESULT: 0x{hr:X8})");
					throw new WebAuthnException($"Failed to create credential: {errorName} (HRESULT: 0x{hr:X8})");
				}

				var attestation = Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_CREDENTIAL_ATTESTATION>(pAttestation);
				Log($"MakeCredential OK: attestation v{attestation.dwVersion}, format={attestation.pwszFormatType}, " +
				    $"transport={attestation.dwUsedTransport}, credId {attestation.cbCredentialId} байт");
				Log($"  Credential ID: {DumpBytes(attestation.pbCredentialId, attestation.cbCredentialId)}");

				if (attestation.cbCredentialId == 0 || attestation.pbCredentialId == IntPtr.Zero)
					throw new WebAuthnException("Credential ID is empty");

				// Проверяем, что аутентификатор действительно включил hmac-secret/PRF для credential
				bool hmacSecretEnabled = ReadHmacSecretExtensionOutput(attestation.Extensions);
				bool prfEnabled = attestation.dwVersion >= WebAuthnApi.WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5 && attestation.bPrfEnabled;
				byte[] prfSecret = attestation.dwVersion >= WebAuthnApi.WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7
					? ReadHmacSecret(attestation.pHmacSecret)
					: null;
				Log($"  hmac-secret ext output: {hmacSecretEnabled}, bPrfEnabled: {prfEnabled}, " +
				    $"PRF secret при создании: {(prfSecret == null ? "нет" : prfSecret.Length + " байт")}");

				if (!hmacSecretEnabled && !prfEnabled && prfSecret == null)
				{
					Log("❌ Аутентификатор НЕ включил hmac-secret/PRF для credential");
					throw new WebAuthnException(
						"Аутентификатор не поддерживает hmac-secret/PRF. " +
						"Используйте FIDO2-ключ с поддержкой hmac-secret (YubiKey 5, SoloKey и т.п.) " +
						"или телефон с менеджером паролей, поддерживающим PRF.");
				}

				return new CredentialCreationResult
				{
					CredentialId = CopyBytes(attestation.pbCredentialId, attestation.cbCredentialId),
					PrfSecret = prfSecret
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
		/// Читает первое значение из PWEBAUTHN_HMAC_SECRET_SALT (результат hmac-secret/PRF); null, если пусто
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
		/// Ищет в выходных расширениях attestation "hmac-secret" со значением BOOL TRUE
		/// </summary>
		private static bool ReadHmacSecretExtensionOutput(WebAuthnApi.WEBAUTHN_EXTENSIONS extensions)
		{
			int extSize = Marshal.SizeOf(typeof(WebAuthnApi.WEBAUTHN_EXTENSION));
			for (uint i = 0; i < extensions.cExtensions && extensions.pExtensions != IntPtr.Zero; i++)
			{
				var ext = Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_EXTENSION>(extensions.pExtensions + (int)(i * extSize));
				Log($"  ext[{i}]: {ext.pwszExtensionIdentifier}, {ext.cbExtension} байт");
				if (ext.pwszExtensionIdentifier == WebAuthnApi.WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET
				    && ext.cbExtension >= sizeof(int) && ext.pvExtension != IntPtr.Zero)
				{
					return Marshal.ReadInt32(ext.pvExtension) != 0;
				}
			}
			return false;
		}

		/// <summary>
		/// Получает PRF secret от аутентификатора используя сохраненный credential ID.
		/// Возвращает детерминированный ключ (32 байта), который используется как мастер-ключ.
		/// </summary>
		public static byte[] GetPrfSecret(IntPtr windowHandle, byte[] credentialId)
		{
			if (credentialId == null || credentialId.Length == 0)
				throw new ArgumentException("Credential ID cannot be null or empty", nameof(credentialId));

			Log($"Получение hmac-secret: RP ID=\"{RP_ID}\", API v{GetApiVersion()}, credId {credentialId.Length} байт");

			IntPtr pClientDataJson = IntPtr.Zero;
			IntPtr pCredentialId = IntPtr.Zero;
			IntPtr pCredential = IntPtr.Zero;
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

				pCredentialId = AllocBytes(credentialId);
				pCredential = AllocStruct(new WebAuthnApi.WEBAUTHN_CREDENTIAL
				{
					dwVersion = 1,
					cbId = (uint)credentialId.Length,
					pbId = pCredentialId,
					pwszCredentialType = WebAuthnApi.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
				});

				// Соль: WEBAUTHN_HMAC_SECRET_SALT_VALUES → pGlobalHmacSalt → WEBAUTHN_HMAC_SECRET_SALT → PRF_SALT
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

				var options = new WebAuthnApi.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
				{
					dwVersion = WebAuthnApi.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
					dwTimeoutMilliseconds = TIMEOUT_MS,
					CredentialList = new WebAuthnApi.WEBAUTHN_CREDENTIALS { cCredentials = 1, pCredentials = pCredential },
					dwAuthenticatorAttachment = WebAuthnApi.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
					dwUserVerificationRequirement = WebAuthnApi.WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
					pHmacSecretSaltValues = pSaltValues
				};

				Log($"GetAssertion: options v{options.dwVersion}, pHmacSecretSaltValues (global salt {PRF_SALT.Length} байт)");
				int hr = WebAuthnApi.WebAuthNAuthenticatorGetAssertion(
					windowHandle, RP_ID, ref clientData, ref options, out pAssertion);

				if (hr != 0)
				{
					string errorName = WebAuthnApi.WebAuthNGetErrorName(hr);
					Log($"ОШИБКА GetAssertion: {errorName} (HRESULT: 0x{hr:X8})");
					throw new WebAuthnException($"Failed to get assertion: {errorName} (HRESULT: 0x{hr:X8})");
				}

				var assertion = Marshal.PtrToStructure<WebAuthnApi.WEBAUTHN_ASSERTION>(pAssertion);
				Log($"GetAssertion OK: assertion v{assertion.dwVersion}, authData {assertion.cbAuthenticatorData} байт, " +
				    $"credId {assertion.Credential.cbId} байт, userId {assertion.cbUserId} байт, " +
				    $"extensions={assertion.Extensions.cExtensions}, pHmacSecret=0x{assertion.pHmacSecret.ToString("X")}");

				if (assertion.dwVersion < WebAuthnApi.WEBAUTHN_ASSERTION_VERSION_3)
					throw new WebAuthnException($"Assertion v{assertion.dwVersion} не содержит pHmacSecret (требуется v3+)");

				byte[] prfSecret = ReadHmacSecret(assertion.pHmacSecret);
				if (prfSecret == null)
				{
					Log("❌ Аутентификатор не вернул hmac-secret");
					throw new WebAuthnException(
						"hmac-secret not returned by authenticator. " +
						"Убедитесь, что credential был создан с hmac-secret/PRF и аутентификатор его поддерживает.");
				}

				Log($"✓ hmac-secret получен, {prfSecret.Length} байт");
				return prfSecret;
			}
			finally
			{
				if (pAssertion != IntPtr.Zero) WebAuthnApi.WebAuthNFreeAssertion(pAssertion);
				if (pSaltValues != IntPtr.Zero) Marshal.FreeHGlobal(pSaltValues);
				if (pSalt != IntPtr.Zero) Marshal.FreeHGlobal(pSalt);
				if (pSaltBytes != IntPtr.Zero) Marshal.FreeHGlobal(pSaltBytes);
				if (pCredential != IntPtr.Zero) Marshal.FreeHGlobal(pCredential);
				if (pCredentialId != IntPtr.Zero) Marshal.FreeHGlobal(pCredentialId);
				if (pClientDataJson != IntPtr.Zero) Marshal.FreeHGlobal(pClientDataJson);
			}
		}

		/// <summary>
		/// Создает JSON для ClientData со случайным challenge
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
	}

	/// <summary>
	/// Результат создания credential
	/// </summary>
	public class CredentialCreationResult
	{
		/// <summary>Credential ID — сохранить для последующих GetPrfSecret</summary>
		public byte[] CredentialId { get; set; }

		/// <summary>PRF-секрет, полученный при создании (API 8+), либо null — тогда нужен GetPrfSecret</summary>
		public byte[] PrfSecret { get; set; }
	}

	/// <summary>
	/// Исключение для ошибок WebAuthn
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
