using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using KeePassPasskeyKeyProvider.Browser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class LoopbackServerTests
	{
		private const string HostName = "keepass-fido2.localhost";
		private const string Body = "credentialId=AQID&prf=a+b%2Fc";

		[TestMethod]
		public void ServesPageWithResultPathForItsHost()
		{
			using (var ceremony = new Ceremony())
			{
				// A web page whose domain was rebound to 127.0.0.1 sends its own Host
				Assert.AreEqual("HTTP/1.1 400 Bad Request", StatusLine(ceremony.Get(ceremony.PagePath, "attacker.example:" + ceremony.Port)));
				// Browsers ask for an icon by themselves
				Assert.AreEqual("HTTP/1.1 404 Not Found", StatusLine(ceremony.Get("/favicon.ico")));

				string resultPath = ceremony.OpenPage();

				Assert.IsTrue(resultPath.StartsWith("/", StringComparison.Ordinal) && resultPath != ceremony.PagePath);
				Assert.AreEqual(0, ceremony.Rejections);
			}
		}

		[TestMethod]
		public void ListensOnBothLoopbackAddresses()
		{
			if (!Socket.OSSupportsIPv6) return;
			using (var ceremony = new Ceremony())
				Assert.AreEqual("HTTP/1.1 200 OK", StatusLine(ceremony.Get(ceremony.PagePath, address: IPAddress.IPv6Loopback)));
		}

		[TestMethod]
		public void PortTakenOnIPv6LoopbackIsNotUsed()
		{
			if (!Socket.OSSupportsIPv6) return;
			// Another process listens on ::1 on the port the server got on 127.0.0.1
			TcpListener squatter = null;
			List<TcpListener> listeners = LoopbackServer.Listen((address, port) =>
			{
				if (address.AddressFamily == AddressFamily.InterNetworkV6 && squatter == null)
				{
					squatter = new TcpListener(IPAddress.IPv6Loopback, port);
					squatter.Start();
				}
				return LoopbackServer.Start(address, port);
			});
			try
			{
				int port = ((IPEndPoint)listeners[0].LocalEndpoint).Port;
				Assert.AreEqual(2, listeners.Count);
				Assert.AreEqual(port, ((IPEndPoint)listeners[1].LocalEndpoint).Port);
				Assert.IsTrue(port != ((IPEndPoint)squatter.LocalEndpoint).Port);
			}
			finally
			{
				listeners.ForEach(l => l.Stop());
				squatter.Stop();
			}
		}

		[TestMethod]
		public void RefusedIPv6LoopbackFailsInsteadOfIPv4Only()
		{
			if (!Socket.OSSupportsIPv6) return;
			Assert.ThrowsException<IOException>(() => LoopbackServer.Listen((address, port) =>
				address.AddressFamily == AddressFamily.InterNetworkV6
					? throw new SocketException((int)SocketError.AccessDenied)
					: LoopbackServer.Start(address, port)));
		}

		[TestMethod]
		public void MissingIPv6LoopbackLeavesIPv4Only()
		{
			List<TcpListener> listeners = LoopbackServer.Listen((address, port) =>
				address.AddressFamily == AddressFamily.InterNetworkV6
					? throw new SocketException((int)SocketError.AddressNotAvailable)
					: LoopbackServer.Start(address, port));
			try
			{
				Assert.AreEqual(1, listeners.Count);
				Assert.AreEqual(AddressFamily.InterNetwork, listeners[0].LocalEndpoint.AddressFamily);
			}
			finally
			{
				listeners.ForEach(l => l.Stop());
			}
		}

		[TestMethod]
		public void AcceptsOneResultWithThePageSecret()
		{
			using (var ceremony = new Ceremony())
			{
				string resultPath = ceremony.OpenPage();

				Assert.AreEqual("HTTP/1.1 204 No Content", StatusLine(ceremony.Post(resultPath, ceremony.Origin)));
				Assert.AreEqual("HTTP/1.1 410 Gone", StatusLine(ceremony.Post(resultPath, ceremony.Origin)));
				Assert.AreEqual(1, ceremony.Results.Count);
				Assert.AreEqual("AQID", ceremony.Results[0]["credentialId"]);
				Assert.AreEqual("a b/c", ceremony.Results[0]["prf"]);
				Assert.AreEqual(0, ceremony.Rejections);
			}
		}

		[TestMethod]
		public void SecondGetOfThePageStopsTheCeremony()
		{
			// Whoever gets the page first has its secret: if it was not the browser, the browser's request fails visibly
			using (var ceremony = new Ceremony())
			{
				string resultPath = ceremony.OpenPage();

				Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(ceremony.Get(ceremony.PagePath)));
				ceremony.AssertStopped(resultPath);
			}
		}

		[TestMethod]
		public void WrongUrlTokenStopsTheCeremony()
		{
			foreach (string path in new[] { "/", "/" + BrowserWebAuthn.Base64Url(TestData.Random(32)) })
			{
				using (var ceremony = new Ceremony())
				{
					Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(ceremony.Get(path)));
					Assert.AreEqual("HTTP/1.1 410 Gone", StatusLine(ceremony.Get(ceremony.PagePath)));
					Assert.AreEqual(1, ceremony.Rejections);
				}
			}
		}

		[TestMethod]
		public void PostWithoutPageSecretStopsTheCeremony()
		{
			// The URL token is on a command line that other local users can read; it does not authorize a result
			using (var ceremony = new Ceremony())
			{
				string resultPath = ceremony.OpenPage();

				Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(ceremony.Post(ceremony.PagePath, ceremony.Origin)));
				ceremony.AssertStopped(resultPath);
			}
		}

		[TestMethod]
		public void PostWithWrongPageSecretStopsTheCeremony()
		{
			using (var ceremony = new Ceremony())
			{
				string resultPath = ceremony.OpenPage();

				Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(ceremony.Post("/" + BrowserWebAuthn.Base64Url(TestData.Random(32)), ceremony.Origin)));
				ceremony.AssertStopped(resultPath);
			}
		}

		[TestMethod]
		public void PostFromAnotherOriginStopsTheCeremony()
		{
			foreach (string origin in new[] { null, "http://attacker.example", "http://localhost" })
			{
				using (var ceremony = new Ceremony())
				{
					string resultPath = ceremony.OpenPage();

					Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(ceremony.Post(resultPath, origin)));
					ceremony.AssertStopped(resultPath);
				}
			}
		}

		[TestMethod]
		public void ResultWithoutCodeIsRefused()
		{
			using (var ceremony = new Ceremony(requireCode: true))
			{
				string resultPath = ceremony.OpenPage();

				AssertWrongCode(ceremony.Post(resultPath, ceremony.Origin), 2);
				Assert.AreEqual(0, ceremony.Results.Count);
				Assert.AreEqual(0, ceremony.Rejections);
			}
		}

		[TestMethod]
		public void RightCodeIsCheckedAndAcceptedWithTheResult()
		{
			using (var ceremony = new Ceremony(requireCode: true))
			{
				string resultPath = ceremony.OpenPage();

				// A check does not consume the result
				for (int i = 0; i < 2; i++)
					Assert.AreEqual("HTTP/1.1 204 No Content", StatusLine(ceremony.Post(resultPath, ceremony.Origin, "check=1&code=" + ceremony.Code)));
				Assert.AreEqual(0, ceremony.Results.Count);

				Assert.AreEqual("HTTP/1.1 204 No Content", StatusLine(ceremony.Post(resultPath, ceremony.Origin, "code=" + ceremony.Code + "&" + Body)));
				Assert.AreEqual(1, ceremony.Results.Count);
				Assert.AreEqual("AQID", ceremony.Results[0]["credentialId"]);
				Assert.AreEqual(0, ceremony.Rejections);
			}
		}

		[TestMethod]
		public void ThirdWrongCodeStopsTheCeremony()
		{
			using (var ceremony = new Ceremony(requireCode: true))
			{
				string resultPath = ceremony.OpenPage();
				string wrong = WrongCode(ceremony.Code);

				// Checks and results count together
				AssertWrongCode(ceremony.Post(resultPath, ceremony.Origin, "check=1&code=" + wrong), 2);
				AssertWrongCode(ceremony.Post(resultPath, ceremony.Origin, "code=" + wrong + "&" + Body), 1);
				Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(ceremony.Post(resultPath, ceremony.Origin, "check=1&code=" + wrong)));
				Assert.AreEqual(LoopbackServer.Rejection.WrongCode, ceremony.Reason);

				// The fourth attempt is refused even with the right code
				Assert.AreEqual("HTTP/1.1 410 Gone", StatusLine(ceremony.Post(resultPath, ceremony.Origin, "code=" + ceremony.Code + "&" + Body)));
				Assert.AreEqual(1, ceremony.Rejections);
				Assert.AreEqual(0, ceremony.Results.Count);
			}
		}

		[TestMethod]
		public void CodeIsNeverSentToTheBrowser()
		{
			using (var ceremony = new Ceremony(requireCode: true))
			{
				string code = ceremony.Code;
				string page = ceremony.Get(ceremony.PagePath);
				string resultPath = Ceremony.ResultPath(page);
				var responses = new[]
				{
					page,
					ceremony.Post(resultPath, ceremony.Origin, "check=1&code=" + WrongCode(code)),
					ceremony.Post(resultPath, ceremony.Origin, "check=1&code=" + code),
					ceremony.Post(resultPath, ceremony.Origin, "code=" + code + "&" + Body)
				};

				Assert.IsFalse(ceremony.Url.Contains(code));
				foreach (string response in responses)
					Assert.IsFalse(response.Contains(code));
				Assert.AreEqual(1, ceremony.Results.Count);
			}
		}

		[TestMethod]
		public void CodesAreSixRandomDigits()
		{
			var codes = new HashSet<string>();
			for (int i = 0; i < 1000; i++)
			{
				string code = LoopbackServer.NewCode();
				Assert.IsTrue(code.Length == 6 && code.All(c => c >= '0' && c <= '9'));
				codes.Add(code);
			}
			// Two equal codes among 1000 are expected about once in two runs
			Assert.IsTrue(codes.Count > 990);
		}

		[TestMethod]
		public void JsonIsSafeInsideScriptElement()
		{
			Assert.AreEqual("\"\\u003c/script\\u003e \\u0026 \\\"\\\\ \\u000a\"", BrowserWebAuthn.Json("</script> & \"\\ \n"));
		}

		[TestMethod]
		public void Base64UrlRoundTrips()
		{
			byte[] data = { 0xfb, 0xff, 0x00, 0x3e };

			Assert.AreEqual("-_8APg", BrowserWebAuthn.Base64Url(data));
			CollectionAssert.AreEqual(data, BrowserWebAuthn.FromBase64Url("-_8APg"));
			Assert.IsNull(BrowserWebAuthn.FromBase64Url("abcde"));
			Assert.IsNull(BrowserWebAuthn.FromBase64Url("ab$d"));
		}

		private static string StatusLine(string response)
		{
			return response.Substring(0, response.IndexOf("\r\n", StringComparison.Ordinal));
		}

		private static string WrongCode(string code)
		{
			return ((int.Parse(code, CultureInfo.InvariantCulture) + 1) % 1000000).ToString("D6", CultureInfo.InvariantCulture);
		}

		/// <summary>A wrong code: the page is told how many attempts are left</summary>
		private static void AssertWrongCode(string response, int attemptsLeft)
		{
			Assert.AreEqual("HTTP/1.1 422 Unprocessable Entity", StatusLine(response));
			Assert.IsTrue(response.EndsWith("\r\n\r\n" + attemptsLeft, StringComparison.Ordinal));
		}

		/// <summary>Server with a page that shows its result path, and the callbacks it made</summary>
		private sealed class Ceremony : IDisposable
		{
			private const string PagePrefix = "<p>";
			private const string PageSuffix = "</p>";

			private readonly LoopbackServer server;
			private int rejections;

			public Ceremony(bool requireCode = false)
			{
				server = new LoopbackServer(HostName, resultPath => PagePrefix + resultPath + PageSuffix, Results.Add,
					reason =>
					{
						Reason = reason;
						Interlocked.Increment(ref rejections);
					},
					requireCode);
			}

			public List<Dictionary<string, string>> Results { get; } = new List<Dictionary<string, string>>();

			public int Rejections => Volatile.Read(ref rejections);

			public LoopbackServer.Rejection Reason { get; private set; }

			public string Code => server.Code;

			public string Url => server.Url;

			public int Port => server.Port;

			public string Origin => "http://" + HostName + ":" + Port;

			public string PagePath => new Uri(server.Url).AbsolutePath;

			/// <summary>Gets the page as the browser does; returns the result path it carries</summary>
			public string OpenPage()
			{
				return ResultPath(Get(PagePath));
			}

			/// <summary>Result path from the response with the page</summary>
			public static string ResultPath(string response)
			{
				Assert.AreEqual("HTTP/1.1 200 OK", StatusLine(response));
				Assert.IsTrue(response.EndsWith(PageSuffix, StringComparison.Ordinal));
				int start = response.LastIndexOf(PagePrefix, StringComparison.Ordinal) + PagePrefix.Length;
				return response.Substring(start, response.Length - PageSuffix.Length - start);
			}

			/// <summary>The ceremony ended with one rejection: the page's own result is no longer accepted</summary>
			public void AssertStopped(string resultPath)
			{
				Assert.AreEqual("HTTP/1.1 410 Gone", StatusLine(Post(resultPath, Origin)));
				Assert.AreEqual(1, Rejections);
				Assert.AreEqual(0, Results.Count);
			}

			public string Get(string path, string host = null, IPAddress address = null)
			{
				return Send(address ?? IPAddress.Loopback, $"GET {path} HTTP/1.1\r\nHost: {host ?? HostName + ":" + Port}\r\n\r\n");
			}

			public string Post(string path, string origin, string body = Body)
			{
				string originHeader = origin != null ? $"Origin: {origin}\r\n" : string.Empty;
				return Send(IPAddress.Loopback, $"POST {path} HTTP/1.1\r\nHost: {HostName}:{Port}\r\n{originHeader}" +
				                                $"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {body.Length}\r\n\r\n{body}");
			}

			public void Dispose()
			{
				server.Dispose();
			}

			private string Send(IPAddress address, string request)
			{
				using (var client = new TcpClient(address.AddressFamily))
				{
					client.Connect(address, Port);
					NetworkStream stream = client.GetStream();
					byte[] data = Encoding.ASCII.GetBytes(request);
					stream.Write(data, 0, data.Length);
					using (var reader = new StreamReader(stream, Encoding.UTF8))
						return reader.ReadToEnd();
				}
			}
		}
	}
}
