using System;
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

		// Line breaks in .resx depend on the checkout (LF or CRLF); a multiline TextBox shows a lone LF as nothing
		private static string Get([CallerMemberName] string name = null) =>
			(manager.GetString(name, culture) ?? name).Replace("\r\n", "\n").Replace("\n", Environment.NewLine);

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
		public static string BrowserCodeCaption => Get();
		public static string BrowserCodeRejected => Get();
		public static string BrowserCreateWaiting => Get();
		public static string BrowserCreateWaitingCode => Get();
		public static string BrowserInvalidAnswer => Get();
		public static string BrowserOpenAgain => Get();
		public static string BrowserOpenFailed => Get();
		public static string BrowserOpenPage => Get();
		public static string BrowserPageButton => Get();
		public static string BrowserPageCancelled => Get();
		public static string BrowserPageCodeFormat => Get();
		public static string BrowserPageCodeLabel => Get();
		public static string BrowserPageCodeWrong => Get();
		public static string BrowserPageCreate => Get();
		public static string BrowserPageDone => Get();
		public static string BrowserPageExists => Get();
		public static string BrowserPageFailed => Get();
		public static string BrowserPageGet => Get();
		public static string BrowserPageNextStep => Get();
		public static string BrowserPageNoPrf => Get();
		public static string BrowserPageStopped => Get();
		public static string BrowserPageTitleCreate => Get();
		public static string BrowserPageTitleCreateNamed => Get();
		public static string BrowserPageTitleGet => Get();
		public static string BrowserPageTitleGetNamed => Get();
		public static string BrowserPageWorking => Get();
		public static string BrowserRejected => Get();
		public static string BrowserTimedOut => Get();
		public static string BrowserUnlockWaiting => Get();
		public static string Bytes => Get();
		public static string Cancel => Get();
		public static string CannotOpenDatabase => Get();
		public static string ChangeNotSaved => Get();
		public static string CheckApi => Get();
		public static string ClassicDevicesElsewhere => Get();
		public static string Close => Get();
		public static string Continue => Get();
		public static string CorruptedDeviceRecord => Get();
		public static string CorruptedKdbxHeader => Get();
		public static string CreateCredentialDescription => Get();
		public static string CreateCredentialDescriptionBrowser => Get();
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
		public static string DiagCheckApiHint => Get();
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
		public static string DiagLibfido2Loaded => Get();
		public static string DiagPinAgain => Get();
		public static string DiagPlatformAvailable => Get();
		public static string DiagPlatformCheckFailed => Get();
		public static string DiagPlatformUnavailable => Get();
		public static string DiagPossibleCauses => Get();
		public static string DiagPrfEmpty => Get();
		public static string DiagPrfSuccess => Get();
		public static string DiagPrfTestConfirm => Get();
		public static string DiagPrfTestConfirmBrowser => Get();
		public static string DiagReady => Get();
		public static string DiagRecommendation1 => Get();
		public static string DiagRecommendation2 => Get();
		public static string DiagRecommendation3 => Get();
		public static string DiagRecommendation4 => Get();
		public static string DiagRecommendations => Get();
		public static string DiagResultSuitable => Get();
		public static string DiagResultUnsuitable => Get();
		public static string DiagSecretLength => Get();
		public static string DiagSecretMatches => Get();
		public static string DiagSecretMismatch => Get();
		public static string DiagStartingPrfTest => Get();
		public static string DiagStep1Creating => Get();
		public static string DiagStep2Getting => Get();
		public static string DiagSystemReady => Get();
		public static string DiagTestCancelled => Get();
		public static string DiagTestFinished => Get();
		public static string DiagUnexpectedError => Get();
		public static string DiagWaitingForHello => Get();
		public static string DiagnosticsTitle => Get();
		public static string Done => Get();
		public static string DontAskAgain => Get();
		public static string EarlierVersionDeviceSuffix => Get();
		public static string EnterDeviceName => Get();
		public static string Fido2AccessHint => Get();
		public static string Fido2DeviceError => Get();
		public static string Fido2LibraryMissing => Get();
		public static string Fido2NoAnswer => Get();
		public static string Fido2NoCredential => Get();
		public static string Fido2NoDevice => Get();
		public static string Fido2PinAuthBlocked => Get();
		public static string Fido2PinBlocked => Get();
		public static string Fido2PinNotAccepted => Get();
		public static string Fido2PinNotSet => Get();
		public static string Fido2Timeout => Get();
		public static string Fido2Unsupported => Get();
		public static string Fido2UserVerificationFailed => Get();
		public static string GetAssertionFailed => Get();
		public static string GetListFailed => Get();
		public static string HelloCleanupButton => Get();
		public static string HelloCredentialsGroup => Get();
		public static string HmacSecretNotReturned => Get();
		public static string IWroteItDown => Get();
		public static string KeepDevicesCheckBox => Get();
		public static string Later => Get();
		public static string MakeAllPortable => Get();
		public static string MakePortable => Get();
		public static string MakePortableConfirm => Get();
		public static string MakePortableDone => Get();
		public static string MakePortableDoneHello => Get();
		public static string MakePortableFailed => Get();
		public static string MakePortableSameDevice => Get();
		public static string MakePortableSameDeviceBrowser => Get();
		public static string MakePortableVersionWarning => Get();
		public static string MasterKeyNotFido2 => Get();
		public static string MasterKeyNotFido2Hint => Get();
		public static string NewDeviceNameLabel => Get();
		public static string NoDeviceRecords => Get();
		public static string NoRecoveryPhrase => Get();
		public static string NoUnusedCredentials => Get();
		public static string Open => Get();
		public static string OpenWithRecoveryPhrase => Get();
		public static string OperationCancelled => Get();
		public static string PhraseChecksumMismatch => Get();
		public static string PhraseUnknownWord => Get();
		public static string PhraseWordCount => Get();
		public static string PinAttemptsLeft => Get();
		public static string PinFewAttempts => Get();
		public static string PinInRowRule => Get();
		public static string PinLastInRow => Get();
		public static string PinRefusedEarlier => Get();
		public static string PinTitle => Get();
		public static string PinWrong => Get();
		public static string PortableReminder => Get();
		public static string PrfDiagnosticsButton => Get();
		public static string PrfTest => Get();
		public static string ReadDeviceRecordsFailed => Get();
		public static string ReadHeaderRecordsFailed => Get();
		public static string RecordsNotAuthentic => Get();
		public static string RecoveryInputDescription => Get();
		public static string RecoveryInputTitle => Get();
		public static string RecoveryPhraseCreated => Get();
		public static string RecoveryPhraseInstructions => Get();
		public static string RecoveryPhraseMismatch => Get();
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
		public static string SecurityKeyPin => Get();
		public static string SecurityKeyTouch => Get();
		public static string SigningKeyInvalid => Get();
		public static string SingleDeviceWarning => Get();
		public static string StatusDatabaseMissing => Get();
		public static string StatusInUse => Get();
		public static string StatusLocationUnavailable => Get();
		public static string StatusNotInDatabase => Get();
		public static string StatusPathUnknown => Get();
		public static string TransportBluetooth => Get();
		public static string TransportDefault => Get();
		public static string TransportNfc => Get();
		public static string TransportPhone => Get();
		public static string TransportThisComputer => Get();
		public static string TransportUsb => Get();
		public static string TryOtherDevicesQuestion => Get();
		public static string UnexpectedError => Get();
		public static string UnknownCredential => Get();
		public static string UnknownDeviceKind => Get();
		public static string Unnamed => Get();
		public static string UnsupportedDeviceRecordsVersion => Get();
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
