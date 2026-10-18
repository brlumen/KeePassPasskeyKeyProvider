using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePassLib.Utility;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider.Fido2
{
	/// <summary>
	/// <see cref="Fido2Authenticator"/> in KeePass's UI. The request runs on a worker thread; the UI thread shows the wait
	/// dialog only when a key needs the user (PIN or touch), so nothing is shown when no connected key holds a credential.
	/// The PIN dialog is shown over the wait dialog; after a wrong PIN it is shown again. Cancel in the wait dialog
	/// cancels the request on the key.
	/// </summary>
	internal sealed class SecurityKeyPrompt : IFido2Prompt
	{
		private readonly WaitForm form;
		private readonly CancellationToken cancellation;
		private readonly ManualResetEvent userNeeded;
		private bool wrongPin;

		private SecurityKeyPrompt(WaitForm form, CancellationToken cancellation, ManualResetEvent userNeeded)
		{
			this.form = form;
			this.cancellation = cancellation;
			this.userNeeded = userNeeded;
		}

		/// <summary>PRF secret of a credential from the allowList on a connected security key (see <see cref="Fido2Authenticator.GetPrfSecret"/>)</summary>
		/// <exception cref="Fido2Exception">No secret; <see cref="Fido2Exception.KeyNotFound"/>: nothing was asked of the user</exception>
		public static PrfResult GetPrfSecret(IWin32Window owner, string rpId, IList<byte[]> allowList)
		{
			using (var form = new WaitForm(""))
			using (var cancellation = new CancellationTokenSource())
			using (var userNeeded = new ManualResetEvent(false))
			using (var done = new ManualResetEvent(false))
			{
				var prompt = new SecurityKeyPrompt(form, cancellation.Token, userNeeded);
				PrfResult result = null;
				Exception error = null;
				var worker = new Thread(() =>
				{
					try
					{
						result = prompt.Run(rpId, allowList);
					}
					catch (Exception ex)
					{
						error = ex;
					}
					finally
					{
						// Before done: the dialog is not disposed yet
						form.Finish(DialogResult.OK);
						done.Set();
					}
				}) { IsBackground = true, Name = "KeePassPasskeyKeyProvider security key" };
				worker.Start();

				// Done first: a request that ended without the user shows no dialog
				if (WaitHandle.WaitAny(new WaitHandle[] { done, userNeeded }) == 1 && form.ShowDialog(owner) != DialogResult.OK)
					cancellation.Cancel();
				// libfido2 returns at once after the cancel request
				done.WaitOne();

				if (error != null)
					ExceptionDispatchInfo.Capture(error).Throw();
				if (cancellation.IsCancellationRequested)
				{
					// The key was touched just as the dialog was cancelled
					if (result != null)
						MemUtil.ZeroByteArray(result.PrfSecret);
					throw new Fido2Exception(Fido2Error.Cancelled);
				}
				return result;
			}
		}

		/// <summary>The request, repeated after a wrong PIN</summary>
		private PrfResult Run(string rpId, IList<byte[]> allowList)
		{
			while (true)
			{
				try
				{
					return Fido2Authenticator.GetPrfSecret(rpId, allowList, this, cancellation);
				}
				catch (Fido2Exception ex) when (ex.Error == Fido2Error.PinInvalid)
				{
					wrongPin = true;
				}
			}
		}

		public byte[] GetPin(string device, int? retriesLeft)
		{
			form.SetMessage(string.Format(Strings.SecurityKeyPin, device));
			userNeeded.Set();

			bool retry = wrongPin;
			var answer = new TaskCompletionSource<byte[]>();
			using (cancellation.Register(() => answer.TrySetCanceled()))
			{
				// Runs once the wait dialog is shown: userNeeded makes the UI thread show it
				form.Post(() =>
				{
					byte[] pin = cancellation.IsCancellationRequested ? null : PinForm.Ask(form, device, retriesLeft, retry);
					// A PIN nobody waits for any more is wiped
					if (!answer.TrySetResult(pin) && pin != null)
						MemUtil.ZeroByteArray(pin);
				});
				try
				{
					return answer.Task.Result;
				}
				catch (AggregateException)
				{
					return null; // cancelled
				}
			}
		}

		public void TouchRequested(string device)
		{
			form.SetMessage(string.Format(Strings.SecurityKeyTouch, device));
			userNeeded.Set();
		}
	}
}
