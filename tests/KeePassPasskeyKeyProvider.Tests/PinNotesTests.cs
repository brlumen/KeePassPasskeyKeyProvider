using System.Collections.Generic;
using KeePassPasskeyKeyProvider.Fido2;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	/// <summary>Warnings of the PIN dialog: the limit that comes first is named</summary>
	[TestClass]
	public class PinNotesTests
	{
		private static string Attempts(int n) => string.Format(Strings.PinAttemptsLeft, n);

		private static string Wrong(int n) => Strings.PinWrong + " " + Attempts(n);

		private static string InRowRule => string.Format(Strings.PinInRowRule, 3);

		[TestMethod]
		public void FirstPromptShowsOnlyAttempts()
		{
			CollectionAssert.AreEqual(new List<string>(), PinNotes.For(null, 0, false));
			CollectionAssert.AreEqual(new[] { Attempts(8) }, PinNotes.For(8, 0, false));
		}

		[TestMethod]
		public void WrongPinsInRowWarnBeforeReinsertionIsNeeded()
		{
			CollectionAssert.AreEqual(new[] { Wrong(7), InRowRule }, PinNotes.For(7, 1, false));
			CollectionAssert.AreEqual(new[] { Wrong(6), Strings.PinLastInRow }, PinNotes.For(6, 2, false));
			CollectionAssert.AreEqual(new[] { Strings.PinWrong, Strings.PinLastInRow }, PinNotes.For(null, 2, false));
		}

		[TestMethod]
		public void FewAttemptsWarnOfReset()
		{
			CollectionAssert.AreEqual(new[] { Attempts(3), Strings.PinFewAttempts }, PinNotes.For(3, 0, false));
			CollectionAssert.AreEqual(new[] { Wrong(3), InRowRule, Strings.PinFewAttempts }, PinNotes.For(3, 1, false));
			// The PIN is blocked before the key would need reinsertion: only that is said
			CollectionAssert.AreEqual(new[] { Wrong(2), Strings.PinFewAttempts }, PinNotes.For(2, 1, false));
			CollectionAssert.AreEqual(new[] { Wrong(1), Strings.PinFewAttempts }, PinNotes.For(1, 2, false));
		}

		[TestMethod]
		public void KeyThatRefusedThePinEarlierIsNamed()
		{
			CollectionAssert.AreEqual(new[] { Attempts(5), Strings.PinRefusedEarlier }, PinNotes.For(5, 0, true));
		}
	}
}
