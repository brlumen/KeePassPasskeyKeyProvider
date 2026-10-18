using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using KeePassPasskeyKeyProvider.Browser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class LoopbackServerTests
	{
		private const string HostName = "keepass-fido2.localhost";
		private const string Page = "<p>page</p>";

		[TestMethod]
		public void ServesPageOnlyAtSecretPathForItsHost()
		{
			using (var server = new LoopbackServer(HostName, Page, _ => { }))
			{
				string path = new Uri(server.Url).AbsolutePath;

				string page = Send(IPAddress.Loopback, server.Port, Get(path, HostName + ":" + server.Port));
				Assert.IsTrue(page.StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal));
				Assert.IsTrue(page.EndsWith(Page, StringComparison.Ordinal));
				Assert.AreEqual("HTTP/1.1 404 Not Found", StatusLine(Send(IPAddress.Loopback, server.Port, Get("/", HostName + ":" + server.Port))));
				// A web page whose domain was rebound to 127.0.0.1 sends its own Host
				Assert.AreEqual("HTTP/1.1 400 Bad Request", StatusLine(Send(IPAddress.Loopback, server.Port, Get(path, "attacker.example:" + server.Port))));
			}
		}

		[TestMethod]
		public void ListensOnBothLoopbackAddresses()
		{
			if (!Socket.OSSupportsIPv6) return;
			using (var server = new LoopbackServer(HostName, Page, _ => { }))
			{
				string path = new Uri(server.Url).AbsolutePath;

				Assert.AreEqual("HTTP/1.1 200 OK", StatusLine(Send(IPAddress.IPv6Loopback, server.Port, Get(path, HostName + ":" + server.Port))));
			}
		}

		[TestMethod]
		public void AcceptsOnePostFromThePage()
		{
			var results = new List<Dictionary<string, string>>();
			using (var server = new LoopbackServer(HostName, Page, results.Add))
			{
				string path = new Uri(server.Url).AbsolutePath;
				string host = HostName + ":" + server.Port;
				string origin = "http://" + host;
				const string body = "credentialId=AQID&prf=a+b%2Fc";

				Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(Send(IPAddress.Loopback, server.Port, Post(path, host, null, body))));
				Assert.AreEqual("HTTP/1.1 403 Forbidden", StatusLine(Send(IPAddress.Loopback, server.Port, Post(path, host, "http://attacker.example", body))));
				Assert.AreEqual(0, results.Count);

				Assert.AreEqual("HTTP/1.1 204 No Content", StatusLine(Send(IPAddress.Loopback, server.Port, Post(path, host, origin, body))));
				Assert.AreEqual("HTTP/1.1 410 Gone", StatusLine(Send(IPAddress.Loopback, server.Port, Post(path, host, origin, body))));
				Assert.AreEqual(1, results.Count);
				Assert.AreEqual("AQID", results[0]["credentialId"]);
				Assert.AreEqual("a b/c", results[0]["prf"]);
			}
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

		private static string Get(string path, string host)
		{
			return $"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n";
		}

		private static string Post(string path, string host, string origin, string body)
		{
			string originHeader = origin != null ? $"Origin: {origin}\r\n" : string.Empty;
			return $"POST {path} HTTP/1.1\r\nHost: {host}\r\n{originHeader}Content-Type: application/x-www-form-urlencoded\r\n" +
			       $"Content-Length: {body.Length}\r\n\r\n{body}";
		}

		private static string Send(IPAddress address, int port, string request)
		{
			using (var client = new TcpClient(address.AddressFamily))
			{
				client.Connect(address, port);
				NetworkStream stream = client.GetStream();
				byte[] data = Encoding.ASCII.GetBytes(request);
				stream.Write(data, 0, data.Length);
				using (var reader = new StreamReader(stream, Encoding.UTF8))
					return reader.ReadToEnd();
			}
		}

		private static string StatusLine(string response)
		{
			return response.Substring(0, response.IndexOf("\r\n", StringComparison.Ordinal));
		}
	}
}
