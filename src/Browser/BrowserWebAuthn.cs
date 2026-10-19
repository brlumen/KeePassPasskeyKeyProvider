using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using KeePassLib.Utility;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider.Browser
{
	/// <summary>
	/// WebAuthn with PRF in the system browser, for systems other than Windows: the plugin serves a page
	/// from <see cref="LoopbackServer"/> at http://keepass-fido2.localhost:port (loopback, a secure context), the page
	/// calls navigator.credentials for portable devices and posts the credential ID and the PRF result back.
	/// The browser offers its own authenticators: this computer (the passkey manager of the browser or system),
	/// a phone by QR code or a security key.
	/// The result is not authenticated beyond the secrets of the server (see <see cref="LoopbackServer"/>): a wrong PRF
	/// secret does not match the owner tag of any wrap (see <see cref="KeyWrap.Open"/>), so a forged answer cannot open
	/// a database.
	/// </summary>
	public static class BrowserWebAuthn
	{
		// Browsers allow only the page's host (or its registrable suffix) as RP ID, so the page is served on this host
		private static string RpId => WebAuthnHelper.RpId(DeviceKind.Portable);
		private const string RpName = "KeePassPasskeyKeyProvider";
		private const string PageResource = "KeePassPasskeyKeyProvider.Browser.webauthn.html";
		private const string RequestPlaceholder = "{{REQUEST}}";
		private const int TimeoutMs = 300000;
		private const int MaxCredentialIdLength = 1023; // WebAuthn limit

		/// <summary>Creates a credential with PRF; the PRF secret is obtained in the same session</summary>
		/// <param name="excludeList">Credentials of the database's portable devices: the browser refuses to register the same authenticator twice</param>
		/// <param name="databaseName">File name shown on the page; null if there is none</param>
		/// <param name="requireCode">The page asks for a confirmation code shown in the wait dialog: needed when the
		/// credential will protect a database, so that a result posted by another local user is not accepted</param>
		/// <exception cref="WebAuthnException">Cancelled, timed out or an invalid answer</exception>
		public static PrfResult CreateCredential(IWin32Window owner, byte[] userId, string userName, IList<byte[]> excludeList,
			string databaseName, bool requireCode)
		{
			var request = new StringBuilder();
			request.Append("{\"mode\":\"create\"");
			request.Append(",\"userId\":").Append(Json(Base64Url(userId)));
			request.Append(",\"userName\":").Append(Json(userName));
			request.Append(",\"exclude\":").Append(JsonArray(excludeList));
			request.Append(",\"code\":").Append(requireCode ? "true" : "false");
			return Run(owner, request, requireCode ? Strings.BrowserCreateWaitingCode : Strings.BrowserCreateWaiting,
				Title(Strings.BrowserPageTitleCreate, Strings.BrowserPageTitleCreateNamed, databaseName), requireCode);
		}

		/// <summary>PRF secret of one of the credentials</summary>
		/// <param name="databaseName">File name shown on the page; null if there is none</param>
		/// <exception cref="WebAuthnException">Cancelled, timed out or an invalid answer</exception>
		public static PrfResult GetPrfSecret(IWin32Window owner, IList<byte[]> allowList, string databaseName)
		{
			var request = new StringBuilder();
			request.Append("{\"mode\":\"get\"");
			request.Append(",\"allow\":").Append(JsonArray(allowList));
			request.Append(",\"code\":false");
			return Run(owner, request, Strings.BrowserUnlockWaiting,
				Title(Strings.BrowserPageTitleGet, Strings.BrowserPageTitleGetNamed, databaseName), false);
		}

		private static string Title(string plain, string named, string databaseName)
		{
			return string.IsNullOrEmpty(databaseName) ? plain : string.Format(named, databaseName);
		}

		private static PrfResult Run(IWin32Window owner, StringBuilder request, string waitText, string title, bool requireCode)
		{
			request.Append(",\"rpId\":").Append(Json(RpId));
			request.Append(",\"rpName\":").Append(Json(RpName));
			request.Append(",\"salt\":").Append(Json(Base64Url(WebAuthnHelper.PrfSalt)));
			request.Append(",\"timeout\":").Append(TimeoutMs.ToString(CultureInfo.InvariantCulture));
			request.Append(",\"text\":{");
			AppendText(request, "title", title, true);
			AppendText(request, "create", Strings.BrowserPageCreate);
			AppendText(request, "get", Strings.BrowserPageGet);
			AppendText(request, "button", Strings.BrowserPageButton);
			AppendText(request, "next", Strings.BrowserPageNextStep);
			AppendText(request, "working", Strings.BrowserPageWorking);
			AppendText(request, "done", Strings.BrowserPageDone);
			AppendText(request, "noPrf", Strings.BrowserPageNoPrf);
			AppendText(request, "cancelled", Strings.BrowserPageCancelled);
			AppendText(request, "exists", Strings.BrowserPageExists);
			AppendText(request, "failed", Strings.BrowserPageFailed);
			AppendText(request, "codeLabel", Strings.BrowserPageCodeLabel);
			AppendText(request, "codeFormat", Strings.BrowserPageCodeFormat);
			AppendText(request, "codeWrong", Strings.BrowserPageCodeWrong);
			AppendText(request, "stopped", Strings.BrowserPageStopped);
			request.Append('}');

			Dictionary<string, string> fields = null;
			var rejection = LoopbackServer.Rejection.UnexpectedRequest;
			using (var form = new BrowserWaitForm(waitText, TimeoutMs))
			using (var server = new LoopbackServer(RpId,
				resultPath => LoadPage(request.ToString() + ",\"resultPath\":" + Json(resultPath) + "}"),
				result =>
				{
					fields = result;
					form.Finish(DialogResult.OK);
				},
				reason =>
				{
					rejection = reason;
					form.Finish(DialogResult.No);
				},
				requireCode))
			{
				form.Url = server.Url;
				form.ShowCode(server.Code);
				DialogResult answer = form.ShowDialog(owner);
				if (answer == DialogResult.OK && fields != null)
					return ToPrfResult(fields);
				throw new WebAuthnException(answer == DialogResult.Abort ? Strings.BrowserTimedOut
					: answer != DialogResult.No ? Strings.OperationCancelled
					: rejection == LoopbackServer.Rejection.WrongCode ? Strings.BrowserCodeRejected
					: Strings.BrowserRejected);
			}
		}

		/// <summary>Opens a URL in the default browser</summary>
		internal static void OpenUrl(string url)
		{
			ProcessStartInfo start;
			if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
				start = new ProcessStartInfo("open", url) { UseShellExecute = false };
			else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
				start = new ProcessStartInfo("xdg-open", url) { UseShellExecute = false };
			else
				start = new ProcessStartInfo(url) { UseShellExecute = true };
			Process.Start(start)?.Dispose();
		}

		/// <exception cref="WebAuthnException">The answer is not a credential ID with a 32-byte PRF secret</exception>
		private static PrfResult ToPrfResult(Dictionary<string, string> fields)
		{
			byte[] credentialId = FromBase64Url(Field(fields, "credentialId"));
			byte[] secret = FromBase64Url(Field(fields, "prf"));
			if (credentialId == null || credentialId.Length == 0 || credentialId.Length > MaxCredentialIdLength ||
			    secret == null || secret.Length != KeyWrap.KeyLength)
			{
				if (secret != null) MemUtil.ZeroByteArray(secret);
				throw new WebAuthnException(Strings.BrowserInvalidAnswer);
			}

			return new PrfResult
			{
				CredentialId = credentialId,
				PrfSecret = secret,
				Transport = ParseTransport(Field(fields, "attachment"), Field(fields, "transports"))
			};
		}

		/// <summary>WEBAUTHN_CTAP_TRANSPORT_* of the authenticator, for the default device label</summary>
		private static uint ParseTransport(string attachment, string transports)
		{
			if (attachment == "platform")
				return WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_INTERNAL;

			uint result = 0;
			foreach (string transport in (transports ?? string.Empty).Split(','))
			{
				switch (transport)
				{
					case "usb": result |= WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_USB; break;
					case "nfc": result |= WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_NFC; break;
					case "ble": result |= WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_BLE; break;
					case "hybrid": result |= WebAuthnApi.WEBAUTHN_CTAP_TRANSPORT_HYBRID; break;
				}
			}
			return result;
		}

		private static string LoadPage(string request)
		{
			using (Stream s = typeof(BrowserWebAuthn).Assembly.GetManifestResourceStream(PageResource))
			{
				if (s == null) throw new InvalidOperationException("Embedded resource not found: " + PageResource);
				using (var reader = new StreamReader(s, Encoding.UTF8))
					return reader.ReadToEnd().Replace(RequestPlaceholder, request);
			}
		}

		private static string Field(Dictionary<string, string> fields, string name)
		{
			string value;
			return fields.TryGetValue(name, out value) ? value : null;
		}

		private static void AppendText(StringBuilder json, string name, string value, bool first = false)
		{
			if (!first) json.Append(',');
			json.Append(Json(name)).Append(':').Append(Json(value));
		}

		private static string JsonArray(IList<byte[]> items)
		{
			var json = new StringBuilder("[");
			for (int i = 0; i < (items?.Count ?? 0); i++)
			{
				if (i > 0) json.Append(',');
				json.Append(Json(Base64Url(items[i])));
			}
			return json.Append(']').ToString();
		}

		/// <summary>
		/// JSON string literal that is also safe inside an HTML script element: &lt;, &gt; and &amp; are escaped,
		/// so a database name cannot close the element
		/// </summary>
		internal static string Json(string value)
		{
			var json = new StringBuilder("\"");
			foreach (char c in value ?? string.Empty)
			{
				if (c == '"' || c == '\\')
					json.Append('\\').Append(c);
				else if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == '\u2028' || c == '\u2029')
					json.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
				else
					json.Append(c);
			}
			return json.Append('"').ToString();
		}

		internal static string Base64Url(byte[] data)
		{
			return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
		}

		/// <summary>Bytes of a base64url string; null if it is missing or invalid</summary>
		internal static byte[] FromBase64Url(string value)
		{
			if (value == null) return null;
			string base64 = value.Replace('-', '+').Replace('_', '/');
			switch (base64.Length % 4)
			{
				case 2: base64 += "=="; break;
				case 3: base64 += "="; break;
				case 1: return null;
			}
			try
			{
				return Convert.FromBase64String(base64);
			}
			catch (FormatException)
			{
				return null;
			}
		}
	}
}
