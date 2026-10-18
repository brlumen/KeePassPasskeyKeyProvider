using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using KeePassPasskeyKeyProvider.Fido2;
using KeePassPasskeyKeyProvider.WebAuthn;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	/// <summary>Logic of the libfido2 layer that needs neither the library nor a key</summary>
	[TestClass]
	public class Fido2AuthenticatorTests
	{
		[TestMethod]
		public void HmacSecretSaltIsWebAuthnPrfTransform()
		{
			byte[] input = TestData.Random(32);
			byte[] expected;
			using (var sha = SHA256.Create())
				expected = sha.ComputeHash(Encoding.ASCII.GetBytes("WebAuthn PRF").Concat(new byte[] { 0 }).Concat(input).ToArray());

			CollectionAssert.AreEqual(expected, Fido2Authenticator.HmacSecretSalt(input));
		}

		[TestMethod]
		public void HmacSecretSaltOfPluginSaltMatchesKnownVector()
		{
			// The salt Windows sends to a security key for the plugin's PRF input: part of the format
			Assert.AreEqual("b1b2c64e27ea65cb003bac6c52ad68ec91726167024694e9ddf9468f948e405e",
				TestData.ToHex(Fido2Authenticator.HmacSecretSalt(WebAuthnHelper.PrfSalt)));
		}

		[DataTestMethod]
		[DataRow(0x2e, Fido2Error.NoCredential)]
		[DataRow(0x31, Fido2Error.PinInvalid)]
		[DataRow(0x37, Fido2Error.PinInvalid)]
		[DataRow(0x32, Fido2Error.PinBlocked)]
		[DataRow(0x34, Fido2Error.PinAuthBlocked)]
		[DataRow(0x35, Fido2Error.PinNotSet)]
		[DataRow(0x36, Fido2Error.PinNotSet)]
		[DataRow(0x3f, Fido2Error.UserVerificationFailed)]
		[DataRow(0x3c, Fido2Error.UserVerificationFailed)]
		[DataRow(0x2f, Fido2Error.Timeout)]
		[DataRow(0x3a, Fido2Error.Timeout)]
		[DataRow(0x2d, Fido2Error.Cancelled)]
		[DataRow(0x27, Fido2Error.Cancelled)]
		[DataRow(0x16, Fido2Error.Unsupported)]
		[DataRow(0x2b, Fido2Error.Unsupported)]
		[DataRow(0x2c, Fido2Error.Unsupported)]
		[DataRow(-1, Fido2Error.DeviceError)] // FIDO_ERR_TX: the key was removed
		[DataRow(-2, Fido2Error.DeviceError)] // FIDO_ERR_RX
		[DataRow(0x7f, Fido2Error.DeviceError)]
		public void ClassifiesLibfido2Errors(int code, Fido2Error expected)
		{
			Assert.AreEqual(expected, Fido2Authenticator.Classify(code));
		}

		[TestMethod]
		public void SkipsOnlyKeysThatCannotHoldTheCredential()
		{
			var skipped = new[] { Fido2Error.NoCredential, Fido2Error.NoAnswer, Fido2Error.Unsupported, Fido2Error.PinNotSet };
			foreach (Fido2Error error in Enum.GetValues(typeof(Fido2Error)))
				Assert.AreEqual(skipped.Contains(error), Fido2Authenticator.IsSkipped(error));
		}

		[TestMethod]
		public void ExceptionMessageHasRetriesAndDetail()
		{
			var ex = new Fido2Exception(Fido2Error.PinInvalid, 3);
			Assert.AreEqual(Strings.PinWrong + " " + string.Format(Strings.PinAttemptsLeft, 3), ex.Message);
			Assert.AreEqual(3, ex.RetriesLeft.Value);
			Assert.IsTrue(ex is WebAuthnException);

			Assert.AreEqual(string.Format(Strings.Fido2DeviceError, "FIDO_ERR_RX (-2)"),
				new Fido2Exception(Fido2Error.DeviceError, detail: "FIDO_ERR_RX (-2)").Message);
			foreach (Fido2Error error in Enum.GetValues(typeof(Fido2Error)))
				Assert.IsTrue(new Fido2Exception(error).Message.Length > 0);
		}

		[TestMethod]
		public void KeyNotFoundOnlyWhenTheUserWasNotAsked()
		{
			var notFound = new[] { Fido2Error.NoDevice, Fido2Error.NoCredential, Fido2Error.NoAnswer, Fido2Error.Unsupported, Fido2Error.PinNotSet };
			foreach (Fido2Error error in Enum.GetValues(typeof(Fido2Error)))
				Assert.AreEqual(notFound.Contains(error), new Fido2Exception(error).KeyNotFound);
		}

		[TestMethod]
		public void UsableCredentialsRespectMaxLength()
		{
			byte[] shortId = TestData.Random(16), maxId = TestData.Random(48), longId = TestData.Random(64);
			var allowList = new List<byte[]> { shortId, maxId, longId, new byte[0], null };

			CollectionAssert.AreEqual(new[] { shortId, maxId }, Fido2Authenticator.UsableCredentials(allowList, 48));
			CollectionAssert.AreEqual(new[] { shortId, maxId, longId }, Fido2Authenticator.UsableCredentials(allowList, 0));
		}

		[TestMethod]
		public void BatchesKeepOrderWithinLimit()
		{
			List<byte[]> ids = Enumerable.Range(0, 5).Select(i => new[] { (byte)i }).ToList();

			List<List<byte[]>> batches = Fido2Authenticator.Batches(ids, 3);
			Assert.AreEqual(2, batches.Count);
			CollectionAssert.AreEqual(ids.Take(3).ToList(), batches[0]);
			CollectionAssert.AreEqual(ids.Skip(3).ToList(), batches[1]);

			Assert.AreEqual(1, Fido2Authenticator.Batches(ids, 0).Count);
			Assert.AreEqual(5, Fido2Authenticator.Batches(ids, 1).Count);
			Assert.AreEqual(0, Fido2Authenticator.Batches(new List<byte[]>(), 3).Count);
		}

		[TestMethod]
		public void MatchCredentialReturnsCopyOfSentId()
		{
			byte[] a = TestData.Random(32), b = TestData.Random(32);
			var sent = new List<byte[]> { a, b };

			byte[] match = Fido2Authenticator.MatchCredential((byte[])b.Clone(), sent);
			CollectionAssert.AreEqual(b, match);
			Assert.IsFalse(ReferenceEquals(b, match));
			Assert.IsNull(Fido2Authenticator.MatchCredential(TestData.Random(32), sent));
			// The ID may be omitted only when the allowList has one credential
			Assert.IsNull(Fido2Authenticator.MatchCredential(new byte[0], sent));
			CollectionAssert.AreEqual(a, Fido2Authenticator.MatchCredential(new byte[0], new List<byte[]> { a }));
		}

		[TestMethod]
		public void RejectsInvalidArgumentsBeforeLoadingLibrary()
		{
			var prompt = new NoPrompt();
			var allowList = new List<byte[]> { TestData.Random(32) };

			Assert.ThrowsException<ArgumentException>(() => Fido2Authenticator.GetPrfSecret("", allowList, prompt, CancellationToken.None));
			Assert.ThrowsException<ArgumentException>(() => Fido2Authenticator.GetPrfSecret("rp", new List<byte[]>(), prompt, CancellationToken.None));
			Assert.ThrowsException<ArgumentException>(() =>
				Fido2Authenticator.GetPrfSecret("rp", new List<byte[]> { new byte[0] }, prompt, CancellationToken.None));
			Assert.ThrowsException<ArgumentNullException>(() => Fido2Authenticator.GetPrfSecret("rp", allowList, null, CancellationToken.None));
		}

		[TestMethod]
		public void MissingLibraryIsPlatformNotSupported()
		{
			var ex = Assert.ThrowsException<PlatformNotSupportedException>(() =>
				new DynamicLibrary("libmissing", new[] { "libkeepass-passkey-missing.so.1" }, "libmissing is required"));
			Assert.AreEqual("libmissing is required", ex.Message);
		}

		private sealed class NoPrompt : IFido2Prompt
		{
			public byte[] GetPin(string device, int? retriesLeft) => null;

			public void TouchRequested(string device)
			{
			}
		}
	}
}
