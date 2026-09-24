using System.Globalization;
using System.Runtime.CompilerServices;
using KeePass;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// UI strings from Strings.resx (English) and Strings.{language}.resx in the KeePass UI language (View → Change Language).
	/// A new string: add it to every Strings*.resx and a property here named after the resource.
	/// </summary>
	internal static class Strings
	{
		private static readonly EmbeddedResourceManager manager =
			new EmbeddedResourceManager(typeof(Strings).FullName, typeof(Strings).Assembly);

		private static readonly CultureInfo culture = GetKeePassCulture();

		private static string Get([CallerMemberName] string name = null) => manager.GetString(name, culture) ?? name;

		private static CultureInfo GetKeePassCulture()
		{
			try
			{
				string code = Program.Translation?.Properties?.Iso6391Code;
				return string.IsNullOrEmpty(code) ? CultureInfo.InvariantCulture : CultureInfo.GetCultureInfo(code);
			}
			catch (CultureNotFoundException)
			{
				return CultureInfo.InvariantCulture;
			}
		}

		public static string ActionIrreversible => Get();
		public static string AddDevice => Get();
		public static string AddDeviceFailed => Get();
		public static string AdditionalDevicesLabel => Get();
		public static string AuthenticationError => Get();
		public static string AuthenticatorNoPrf => Get();
		public static string Back => Get();
		public static string Bytes => Get();
		public static string Cancel => Get();
		public static string CannotOpenDatabase => Get();
		public static string CheckApi => Get();
		public static string Close => Get();
		public static string Continue => Get();
		public static string CorruptedDeviceRecord => Get();
		public static string CorruptedKdbxHeader => Get();
		public static string CorruptedRecoveryRecord => Get();
		public static string CreateCredentialDescription => Get();
		public static string CreateCredentialFailed => Get();
		public static string CreateCredentialTitle => Get();
		public static string CreateRecoveryPhrase => Get();
		public static string DeleteChecked => Get();
		public static string DeleteCredentialsConfirm => Get();
		public static string DeleteCredentialsRisk => Get();
		public static string DeleteCredentialsTitle => Get();
		public static string DeletedCount => Get();
		public static string DeletingCredential => Get();
		public static string DeviceNameLabel => Get();
		public static string DevicesTabInfo => Get();
		public static string DevicesWillBeKept => Get();
		public static string DevicesWillBeRemoved => Get();
		public static string DiagApiAvailable => Get();
		public static string DiagApiRequirement => Get();
		public static string DiagApiUnavailable => Get();
		public static string DiagApiVersion => Get();
		public static string DiagCause1 => Get();
		public static string DiagCause2 => Get();
		public static string DiagCause3 => Get();
		public static string DiagCheckingApi => Get();
		public static string DiagCreateFailed => Get();
		public static string DiagCreationSecret => Get();
		public static string DiagCredentialCreated => Get();
		public static string DiagError => Get();
		public static string DiagErrorType => Get();
		public static string DiagGetSecretFailed => Get();
		public static string DiagHeader => Get();
		public static string DiagIntro1 => Get();
		public static string DiagIntro2 => Get();
		public static string DiagIntro3 => Get();
		public static string DiagKeyMayNotSupport => Get();
		public static string DiagKeyNoPrf => Get();
		public static string DiagKeyNoPrfReason => Get();
		public static string DiagKeySupportsPrf => Get();
		public static string DiagKeyUsable => Get();
		public static string DiagPinAgain => Get();
		public static string DiagPlatformAvailable => Get();
		public static string DiagPlatformCheckFailed => Get();
		public static string DiagPlatformUnavailable => Get();
		public static string DiagPossibleCauses => Get();
		public static string DiagPrfEmpty => Get();
		public static string DiagPrfSuccess => Get();
		public static string DiagPrfTestConfirm => Get();
		public static string DiagReady => Get();
		public static string DiagRecommendation1 => Get();
		public static string DiagRecommendation2 => Get();
		public static string DiagRecommendation3 => Get();
		public static string DiagRecommendation4 => Get();
		public static string DiagRecommendations => Get();
		public static string DiagSecretLength => Get();
		public static string DiagSecretMatches => Get();
		public static string DiagSecretMismatch => Get();
		public static string DiagStartingPrfTest => Get();
		public static string DiagStep1 => Get();
		public static string DiagStep1Creating => Get();
		public static string DiagStep2 => Get();
		public static string DiagStep2Getting => Get();
		public static string DiagSteps => Get();
		public static string DiagSystemReady => Get();
		public static string DiagTestCancelled => Get();
		public static string DiagTestFinished => Get();
		public static string DiagUnexpectedError => Get();
		public static string DiagnosticsTitle => Get();
		public static string Done => Get();
		public static string EnterDeviceName => Get();
		public static string GetAssertionFailed => Get();
		public static string GetListFailed => Get();
		public static string HelloCleanupButton => Get();
		public static string HelloCredentialsGroup => Get();
		public static string HmacSecretNotReturned => Get();
		public static string IWroteItDown => Get();
		public static string KeepDevicesCheckBox => Get();
		public static string MasterKeyNotFido2 => Get();
		public static string MasterKeyNotFido2Hint => Get();
		public static string NewDeviceNameLabel => Get();
		public static string NoDeviceRecords => Get();
		public static string NoRecoveryPhrase => Get();
		public static string NoUnusedCredentials => Get();
		public static string Open => Get();
		public static string OpenWithRecoveryPhrase => Get();
		public static string PhraseChecksumMismatch => Get();
		public static string PhraseUnknownWord => Get();
		public static string PhraseWordCount => Get();
		public static string PrfDiagnosticsButton => Get();
		public static string PrfTest => Get();
		public static string ReadDeviceRecordsFailed => Get();
		public static string ReadHeaderRecordsFailed => Get();
		public static string RecoveryInputDescription => Get();
		public static string RecoveryInputTitle => Get();
		public static string RecoveryPhraseCreated => Get();
		public static string RecoveryPhraseInstructions => Get();
		public static string RecoveryPhraseTitle => Get();
		public static string Refresh => Get();
		public static string RemoveDeviceConfirm => Get();
		public static string RemoveDeviceFailed => Get();
		public static string RemoveDeviceTitle => Get();
		public static string RemovePhrase => Get();
		public static string RemovePhraseConfirm => Get();
		public static string RemovePhraseFailed => Get();
		public static string RemovePhraseTitle => Get();
		public static string RemoveSelectedDevice => Get();
		public static string RemovingDevice => Get();
		public static string RemovingPhrase => Get();
		public static string ReplacePhrase => Get();
		public static string ReplacePhraseConfirm => Get();
		public static string ReplacePhraseTitle => Get();
		public static string SavePhraseFailed => Get();
		public static string SavingPhrase => Get();
		public static string SingleDeviceWarning => Get();
		public static string StatusDatabaseMissing => Get();
		public static string StatusInUse => Get();
		public static string StatusNotInDatabase => Get();
		public static string StatusPathUnknown => Get();
		public static string TransportBluetooth => Get();
		public static string TransportDefault => Get();
		public static string TransportNfc => Get();
		public static string TransportPhone => Get();
		public static string TransportUsb => Get();
		public static string UnexpectedError => Get();
		public static string UnknownCredential => Get();
		public static string Unnamed => Get();
		public static string UnsupportedDeviceRecordsVersion => Get();
		public static string UnsupportedRecoveryRecordVersion => Get();
		public static string UnusedCredentialsHint => Get();
		public static string VerifyPhraseDescription => Get();
		public static string WebAuthnAvailableInfo => Get();
		public static string WebAuthnUnavailable => Get();
		public static string WebAuthnUnavailableRequires => Get();
		public static string WebAuthnUnavailableShort => Get();
		public static string WordMismatch => Get();
		public static string WordNumber => Get();
	}
}
