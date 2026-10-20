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
	/// The PIN dialog is shown over the wait dialog; after a wrong PIN it is shown again, with what further wrong PINs
	/// lead to. Cancel in the wait dialog cancels the request on the key.
	/// </summary>
	internal sealed class SecurityKeyPrompt : IFido2Prompt
	{
		private readonly WaitForm form;
		private readonly CancellationToken cancellation;
		private readonly ManualResetEvent userNeeded;
		private int? pinRetries;
		private int wrongPinsInRow;

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
					// A PIN rejected before it reached the key (too long) is not an attempt
					if (ex.RetriesLeft == null || pinRetries == null || ex.RetriesLeft < pinRetries)
						wrongPinsInRow++;
				}
			}
		}

		public byte[] GetPin(string device, int? retriesLeft)
		{
			form.SetMessage(string.Format(Strings.SecurityKeyPin, device));
			userNeeded.Set();

			pinRetries = retriesLeft;
			List<string> notes = PinNotes.For(retriesLeft, wrongPinsInRow, Fido2Authenticator.PinRefusedEarlier(device));
			// Only "attempts left" with plenty of them is not a warning
			bool warning = wrongPinsInRow > 0 || notes.Count > (retriesLeft != null ? 1 : 0);
			var answer = new TaskCompletionSource<byte[]>();
			using (cancellation.Register(() => answer.TrySetCanceled()))
			{
				// Runs once the wait dialog is shown: userNeeded makes the UI thread show it
				form.Post(() =>
				{
					byte[] pin = cancellation.IsCancellationRequested ? null : PinForm.Ask(form, device, notes, warning);
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

	/// <summary>
	/// Notes in the PIN dialog: attempts left and what further wrong PINs lead to, whichever limit comes first — wrong
	/// PINs in a row (the key must be reinserted) or all attempts (the PIN is blocked, only a reset of the key helps)
	/// </summary>
	internal static class PinNotes
	{
		// CTAP: after this many wrong PINs in a row the key accepts no PIN until it is removed and inserted again
		private const int MaxWrongPinsInRow = 3;
		// Attempts left at which the user is warned that the PIN will be blocked for good
		private const int FewRetries = 3;

		/// <summary>Lines under the PIN box</summary>
		/// <param name="wrongPinsInRow">Wrong PINs for this key in a row in this unlock</param>
		/// <param name="refusedEarlier">The key refused the PIN after wrong PINs in a row earlier and may still refuse it</param>
		public static List<string> For(int? retriesLeft, int wrongPinsInRow, bool refusedEarlier)
		{
			var notes = new List<string>();
			string status = retriesLeft != null ? string.Format(Strings.PinAttemptsLeft, retriesLeft) : null;
			if (wrongPinsInRow > 0)
				status = status == null ? Strings.PinWrong : Strings.PinWrong + " " + status;
			if (status != null)
				notes.Add(status);
			if (refusedEarlier)
				notes.Add(Strings.PinRefusedEarlier);

			int inRowLeft = MaxWrongPinsInRow - wrongPinsInRow;
			if (wrongPinsInRow > 0 && !(retriesLeft <= inRowLeft))
				notes.Add(inRowLeft <= 1 ? Strings.PinLastInRow : string.Format(Strings.PinInRowRule, MaxWrongPinsInRow));
			if (retriesLeft <= FewRetries)
				notes.Add(Strings.PinFewAttempts);
			return notes;
		}
	}
}
