using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class PortableReminderTests
	{
		private static readonly DeviceRecord Classic = new DeviceRecord { Kind = DeviceKind.Classic };

		[TestMethod]
		public void OffersOnlyForClassicDeviceOnce()
		{
			Assert.IsTrue(PortableReminder.ShouldOffer(Classic, true, false, false));

			Assert.IsFalse(PortableReminder.ShouldOffer(new DeviceRecord { Kind = DeviceKind.Portable }, true, false, false));
			Assert.IsFalse(PortableReminder.ShouldOffer(null, true, false, false));
			// A passkey cannot be created or the database saved here
			Assert.IsFalse(PortableReminder.ShouldOffer(Classic, false, false, false));
			// Asked in this session ("Later") or turned off for the database ("Don't ask again")
			Assert.IsFalse(PortableReminder.ShouldOffer(Classic, true, true, false));
			Assert.IsFalse(PortableReminder.ShouldOffer(Classic, true, false, true));
		}

		[TestMethod]
		public void DatabaseIdFollowsVerificationKey()
		{
			byte[] verificationKey = TestData.Random(KeyWrap.PublicKeyLength);
			string id = PortableReminder.DatabaseId(verificationKey);

			Assert.AreEqual(32, id.Length);
			Assert.AreEqual(id, PortableReminder.DatabaseId((byte[])verificationKey.Clone()));
			Assert.IsTrue(id != PortableReminder.DatabaseId(TestData.Random(KeyWrap.PublicKeyLength)));
		}
	}
}
