using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace KeePassPasskeyKeyProvider.Browser
{
	/// <summary>
	/// One-shot HTTP server for a WebAuthn ceremony in the browser, at http://hostName:port. Listens on the same port of
	/// 127.0.0.1 and ::1: the browser resolves a *.localhost name to either, and a foreign server on the other address
	/// would get the page.
	/// The secret path of <see cref="Url"/> reaches the browser on a command line that other local users can read, so
	/// it is single-use: the first GET gets the page. The page carries a second secret, the path of its result: one
	/// form POST there with the page's Origin is accepted and ends the session. Any other request with the expected
	/// Host (a second GET of the page, a wrong secret, a foreign Origin) means that someone else races the browser:
	/// it stops the ceremony, so that they get a visible failure, not a result accepted from them.
	/// Someone who gets the page before the browser could still post a result before the browser's own request stops
	/// the ceremony. Where that matters (a credential that will protect a database) a confirmation code is required:
	/// KeePass shows <see cref="Code"/> only in its own window, the user enters it on the page, and the page checks it
	/// (a POST with the "check" field) and posts it with the result. The server never sends the code; after
	/// <see cref="MaxWrongCodes"/> wrong codes, in checks and results together, the ceremony stops. Not covered:
	/// processes of the same user, which can read the KeePass window or control the browser.
	/// Requests with another Host (DNS rebinding) and for files (icons) are refused without stopping the ceremony.
	/// </summary>
	internal sealed class LoopbackServer : IDisposable
	{
		private const int MaxHeaderLength = 16 * 1024;
		private const int MaxBodyLength = 16 * 1024;
		private const int ReceiveTimeoutMs = 10000;
		private const int PortAttempts = 20;
		internal const int MaxWrongCodes = 3;

		private readonly byte[] page;
		private readonly Action<Dictionary<string, string>> onResult;
		private readonly Action<Rejection> onRejected;
		private readonly List<TcpListener> listeners;
		private readonly string pagePath;
		private readonly string resultPath;
		private readonly string host;
		private readonly string origin;
		private int pageServed;
		private int finished;
		private int codeAttemptsLeft = MaxWrongCodes;

		/// <summary>Why the ceremony was stopped</summary>
		internal enum Rejection
		{
			/// <summary>A second GET of the page, a wrong secret or a foreign Origin</summary>
			UnexpectedRequest,

			/// <summary><see cref="MaxWrongCodes"/> wrong confirmation codes</summary>
			WrongCode
		}

		/// <param name="hostName">Host of the page: a *.localhost name, which browsers resolve to loopback</param>
		/// <param name="page">HTML served once at the secret path of <see cref="Url"/>, built for the secret path that
		/// the page posts its result to</param>
		/// <param name="onResult">Called on a background thread with the fields of the accepted POST</param>
		/// <param name="onRejected">Called on a background thread when the ceremony is stopped.
		/// Only one of the two callbacks is called, once.</param>
		/// <param name="requireCode">The page must present <see cref="Code"/> to post its result</param>
		public LoopbackServer(string hostName, Func<string, string> page, Action<Dictionary<string, string>> onResult,
			Action<Rejection> onRejected, bool requireCode = false)
		{
			pagePath = "/" + NewToken();
			resultPath = "/" + NewToken();
			// The page is built before the code exists: it cannot contain it
			this.page = Encoding.UTF8.GetBytes(page(resultPath));
			Code = requireCode ? NewCode() : null;
			this.onResult = onResult;
			this.onRejected = onRejected;
			listeners = Listen(Start);
			Port = ((IPEndPoint)listeners[0].LocalEndpoint).Port;
			host = hostName + ":" + Port;
			origin = "http://" + host;

			foreach (TcpListener listener in listeners)
				new Thread(() => AcceptLoop(listener)) { IsBackground = true, Name = "KeePassPasskeyKeyProvider HTTP" }.Start();
		}

		public int Port { get; }

		/// <summary>Address of the page; the path is a random single-use token</summary>
		public string Url => origin + pagePath;

		/// <summary>Confirmation code (6 digits) to show only in the KeePass window; null if none is required</summary>
		public string Code { get; }

		public void Dispose()
		{
			Interlocked.Exchange(ref finished, 1);
			foreach (TcpListener listener in listeners)
				listener.Stop();
		}

		/// <summary>
		/// Listeners on the same port of 127.0.0.1 and ::1. If ::1 cannot be bound on the port (another process may
		/// listen there and get the browser's requests), another port is tried. 127.0.0.1 alone only on a system without
		/// IPv6 loopback, where browsers cannot connect to ::1 either.
		/// </summary>
		/// <param name="start">Starts a listener on the address and port (0: any free port)</param>
		/// <exception cref="IOException">No port could be bound on both addresses</exception>
		internal static List<TcpListener> Listen(Func<IPAddress, int, TcpListener> start)
		{
			for (int attempt = 0; attempt < PortAttempts; attempt++)
			{
				TcpListener v4 = start(IPAddress.Loopback, 0);
				if (!Socket.OSSupportsIPv6)
					return new List<TcpListener> { v4 };

				int port = ((IPEndPoint)v4.LocalEndpoint).Port;
				try
				{
					return new List<TcpListener> { v4, start(IPAddress.IPv6Loopback, port) };
				}
				catch (SocketException ex) when (IsMissingAddress(ex.SocketErrorCode))
				{
					return new List<TcpListener> { v4 };
				}
				catch (SocketException)
				{
					v4.Stop(); // taken or refused on ::1: another port
				}
			}
			throw new IOException("No port could be bound on both 127.0.0.1 and ::1");
		}

		/// <summary>The address does not exist on this system, so nobody can listen on it</summary>
		private static bool IsMissingAddress(SocketError error)
		{
			return error == SocketError.AddressNotAvailable || error == SocketError.AddressFamilyNotSupported ||
			       error == SocketError.ProtocolFamilyNotSupported || error == SocketError.ProtocolNotSupported;
		}

		internal static TcpListener Start(IPAddress address, int port)
		{
			var listener = new TcpListener(address, port);
			// Windows lets another process bind the same address and port unless the socket is exclusive
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				listener.ExclusiveAddressUse = true;
			listener.Start();
			return listener;
		}

		/// <summary>Six random decimal digits, uniformly distributed</summary>
		internal static string NewCode()
		{
			byte[] random = new byte[4];
			using (var rng = new RNGCryptoServiceProvider())
			{
				while (true)
				{
					rng.GetBytes(random);
					uint value = BitConverter.ToUInt32(random, 0);
					// The largest multiple of 10^6 below 2^32: values above it would make low codes more likely
					if (value < 4294000000u)
						return (value % 1000000).ToString("D6", CultureInfo.InvariantCulture);
				}
			}
		}

		private static string NewToken()
		{
			byte[] token = new byte[32];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(token);
			return Convert.ToBase64String(token).TrimEnd('=').Replace('+', '-').Replace('/', '_');
		}

		private void AcceptLoop(TcpListener listener)
		{
			while (true)
			{
				TcpClient client;
				try
				{
					client = listener.AcceptTcpClient();
				}
				catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException || ex is InvalidOperationException)
				{
					return; // stopped
				}
				ThreadPool.QueueUserWorkItem(_ => Serve(client));
			}
		}

		private void Serve(TcpClient client)
		{
			using (client)
			{
				try
				{
					client.ReceiveTimeout = ReceiveTimeoutMs;
					client.SendTimeout = ReceiveTimeoutMs;
					NetworkStream stream = client.GetStream();
					Respond(stream, Handle(Request.Read(stream)));
				}
				catch (Exception ex) when (ex is IOException || ex is SocketException || ex is InvalidDataException || ex is ObjectDisposedException)
				{
					// a broken or malformed request: drop the connection
				}
			}
		}

		private Response Handle(Request request)
		{
			// Another site whose name resolves to loopback (DNS rebinding) knows no secrets: it does not stop the ceremony
			if (request.Header("Host") != host)
				return Response.Status(400, "Bad Request");
			if (Volatile.Read(ref finished) != 0)
				return Response.Status(410, "Gone");
			// Browsers ask for icons by themselves; the secrets have no dot
			if (request.Method == "GET" && request.Path.IndexOf('.') >= 0)
				return Response.Status(404, "Not Found");

			if (request.Method == "GET" && IsSecret(request.Path, pagePath) && Interlocked.Exchange(ref pageServed, 1) == 0)
				return Response.Page(page);
			if (request.Method == "POST" && IsSecret(request.Path, resultPath) && request.Header("Origin") == origin)
				return Accept(ParseForm(request.Body));

			// A second GET of the page, a wrong secret or a foreign Origin
			return Reject(Rejection.UnexpectedRequest);
		}

		/// <summary>A form POST of the page: a check of the confirmation code ("check" field) or the result</summary>
		private Response Accept(Dictionary<string, string> fields)
		{
			string code;
			if (Code != null && !(fields.TryGetValue("code", out code) && IsSecret(code, Code)))
			{
				int left = Interlocked.Decrement(ref codeAttemptsLeft);
				return left > 0
					? Response.Text(422, "Unprocessable Entity", left.ToString(CultureInfo.InvariantCulture))
					: Reject(Rejection.WrongCode);
			}
			if (fields.ContainsKey("check"))
				return Response.Status(204, "No Content");

			if (!Finish())
				return Response.Status(410, "Gone");
			onResult(fields);
			return Response.Status(204, "No Content");
		}

		/// <summary>Stops the ceremony (once)</summary>
		private Response Reject(Rejection reason)
		{
			if (Finish())
				onRejected(reason);
			return Response.Status(403, "Forbidden");
		}

		/// <summary>Ends the session; false if it has already ended</summary>
		private bool Finish()
		{
			return Interlocked.Exchange(ref finished, 1) == 0;
		}

		/// <summary>Constant-time comparison with a secret</summary>
		private static bool IsSecret(string value, string secret)
		{
			return KeyWrap.FixedTimeEquals(Encoding.ASCII.GetBytes(value), Encoding.ASCII.GetBytes(secret));
		}

		/// <summary>application/x-www-form-urlencoded fields</summary>
		internal static Dictionary<string, string> ParseForm(byte[] body)
		{
			var fields = new Dictionary<string, string>(StringComparer.Ordinal);
			foreach (string pair in Encoding.ASCII.GetString(body).Split('&'))
			{
				if (pair.Length == 0) continue;
				int eq = pair.IndexOf('=');
				string name = Decode(eq < 0 ? pair : pair.Substring(0, eq));
				fields[name] = eq < 0 ? string.Empty : Decode(pair.Substring(eq + 1));
			}
			return fields;
		}

		private static string Decode(string value)
		{
			return Uri.UnescapeDataString(value.Replace('+', ' '));
		}

		private static void Respond(Stream stream, Response response)
		{
			var head = new StringBuilder();
			head.Append("HTTP/1.1 ").Append(response.Code).Append(' ').Append(response.Reason).Append("\r\n");
			head.Append("Content-Length: ").Append(response.Body.Length).Append("\r\n");
			if (response.Body.Length > 0)
				head.Append("Content-Type: ").Append(response.ContentType).Append("\r\n");
			head.Append("Cache-Control: no-store\r\n");
			head.Append("Referrer-Policy: no-referrer\r\n");
			head.Append("X-Content-Type-Options: nosniff\r\n");
			head.Append("X-Frame-Options: DENY\r\n");
			head.Append("Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
			            "img-src data:; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'\r\n");
			head.Append("Connection: close\r\n\r\n");

			byte[] headBytes = Encoding.ASCII.GetBytes(head.ToString());
			stream.Write(headBytes, 0, headBytes.Length);
			stream.Write(response.Body, 0, response.Body.Length);
			stream.Flush();
		}

		private sealed class Request
		{
			private readonly Dictionary<string, string> headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

			public string Method { get; private set; }

			public string Path { get; private set; }

			public byte[] Body { get; private set; }

			public string Header(string name)
			{
				string value;
				return headers.TryGetValue(name, out value) ? value : null;
			}

			/// <exception cref="InvalidDataException">Not a well-formed request within the size limits</exception>
			public static Request Read(Stream stream)
			{
				string[] lines = ReadHead(stream).Split(new[] { "\r\n" }, StringSplitOptions.None);
				string[] requestLine = lines[0].Split(' ');
				if (requestLine.Length != 3 || !requestLine[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
					throw new InvalidDataException();

				var request = new Request { Method = requestLine[0], Path = requestLine[1] };
				for (int i = 1; i < lines.Length; i++)
				{
					int colon = lines[i].IndexOf(':');
					if (colon <= 0) throw new InvalidDataException();
					string name = lines[i].Substring(0, colon).Trim();
					if (request.headers.ContainsKey(name)) throw new InvalidDataException(); // e.g. a second Host
					request.headers[name] = lines[i].Substring(colon + 1).Trim();
				}

				int length = 0;
				string contentLength = request.Header("Content-Length");
				if (contentLength != null && (!int.TryParse(contentLength, out length) || length < 0 || length > MaxBodyLength))
					throw new InvalidDataException();
				request.Body = ReadExact(stream, length);
				return request;
			}

			/// <summary>Request line and headers up to the empty line (excluded)</summary>
			private static string ReadHead(Stream stream)
			{
				var head = new MemoryStream();
				int matched = 0; // bytes of "\r\n\r\n" seen
				while (matched < 4)
				{
					int b = stream.ReadByte();
					if (b < 0 || head.Length >= MaxHeaderLength) throw new InvalidDataException();
					head.WriteByte((byte)b);
					matched = b == (matched % 2 == 0 ? '\r' : '\n') ? matched + 1 : (b == '\r' ? 1 : 0);
				}
				return Encoding.ASCII.GetString(head.GetBuffer(), 0, (int)head.Length - 4);
			}

			private static byte[] ReadExact(Stream stream, int length)
			{
				byte[] data = new byte[length];
				int read = 0;
				while (read < length)
				{
					int n = stream.Read(data, read, length - read);
					if (n <= 0) throw new InvalidDataException();
					read += n;
				}
				return data;
			}
		}

		private sealed class Response
		{
			public int Code;
			public string Reason;
			public byte[] Body = new byte[0];
			public string ContentType;

			public static Response Status(int code, string reason)
			{
				return new Response { Code = code, Reason = reason };
			}

			public static Response Page(byte[] body)
			{
				return new Response { Code = 200, Reason = "OK", Body = body, ContentType = "text/html; charset=utf-8" };
			}

			public static Response Text(int code, string reason, string text)
			{
				return new Response { Code = code, Reason = reason, Body = Encoding.UTF8.GetBytes(text), ContentType = "text/plain; charset=utf-8" };
			}
		}
	}
}
