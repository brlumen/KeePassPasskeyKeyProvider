using System;
using System.IO;
using System.Security.Cryptography;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassPasskeyKeyProvider.WebAuthn;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeePassPasskeyKeyProvider.Tests
{
	[TestClass]
	public class DeviceKeyStoreTests
	{
		private const string RecordsKey = "KeePassFIDO2.Devices";
		private const string SigningKeyKey = "KeePassFIDO2.SigningKey";

		private readonly byte[] key = TestData.Random(KeyWrap.KeyLength);
		private readonly byte[] deviceSecret = TestData.Random(KeyWrap.KeyLength);
		private readonly byte[] phraseSecret = TestData.Random(KeyWrap.KeyLength);
		private string path;

		[TestInitialize]
		public void Initialize()
		{
			path = Path.GetTempFileName();
		}

		[TestCleanup]
		public void Cleanup()
		{
			File.Delete(path);
		}

		[TestMethod]
		public void RecordsSavedToHeaderOpenAndVerify()
		{
			PwDatabase db = CreateDatabase();

			DeviceRecordSet set = ReadFromFile(db.PublicCustomData.GetByteArray(RecordsKey));

			Assert.IsTrue(set.VerifySignature());
			Assert.AreEqual(1, set.Devices.Count);
			Assert.AreEqual("Device", set.Devices[0].Label);
			CollectionAssert.AreEqual(key, set.Devices[0].Wrap.Open(deviceSecret, set.VerificationKey));
			CollectionAssert.AreEqual(key, set.Recovery.Open(phraseSecret, set.VerificationKey));
		}

		[TestMethod]
		public void ModifiedRecordsFailSignature()
		{
			byte[] records = CreateDatabase().PublicCustomData.GetByteArray(RecordsKey);

			// Every byte before the signature is signed: flip one in the device label
			int labelOffset = records.Length - SigningKey.SignatureLength - 1 - KeyWrap.SerializedLength - 1;
			records[labelOffset] ^= 1;

			Assert.IsFalse(ReadFromFile(records).VerifySignature());
		}

		[TestMethod]
		public void RecordsResignedWithForeignKeyAreRejected()
		{
			// A forger without SK copies the victim's wraps into records signed with their own key pair
			DeviceRecordSet victim = ReadFromFile(CreateDatabase().PublicCustomData.GetByteArray(RecordsKey));
			var forger = new PwDatabase();
			using (SigningKey forgerKey = SigningKey.Generate())
			{
				DeviceKeyStore.SetSigningKey(forger, forgerKey);
				victim.VerificationKey = forgerKey.VerificationKey;
				DeviceKeyStore.Save(forger, victim);
			}

			DeviceRecordSet forged = ReadFromFile(forger.PublicCustomData.GetByteArray(RecordsKey));

			Assert.IsTrue(forged.VerifySignature());
			Assert.ThrowsException<CryptographicException>(() => forged.Devices[0].Wrap.Open(deviceSecret, forged.VerificationKey));
			Assert.ThrowsException<CryptographicException>(() => forged.Recovery.Open(phraseSecret, forged.VerificationKey));
		}

		[TestMethod]
		public void SaveRequiresMatchingSigningKey()
		{
			PwDatabase db = CreateDatabase();
			DeviceRecordSet set = DeviceKeyStore.LoadAll(db);
			using (SigningKey other = SigningKey.Generate())
				set.VerificationKey = other.VerificationKey;

			Assert.ThrowsException<InvalidOperationException>(() => DeviceKeyStore.Save(db, set));
		}

		[TestMethod]
		public void MergedRecordsAndSigningKeyAreRestored()
		{
			PwDatabase db = CreateDatabase();
			byte[] records = db.PublicCustomData.GetByteArray(RecordsKey);
			string signingKey = db.CustomData.Get(SigningKeyKey);

			// File → Import / Synchronize copies the other database's custom data
			PwDatabase other = CreateDatabase();
			db.PublicCustomData.SetByteArray(RecordsKey, other.PublicCustomData.GetByteArray(RecordsKey));
			db.CustomData.Set(SigningKeyKey, other.CustomData.Get(SigningKeyKey));

			Assert.IsTrue(DeviceKeyStore.RestoreIfChanged(db));
			CollectionAssert.AreEqual(records, db.PublicCustomData.GetByteArray(RecordsKey));
			Assert.AreEqual(signingKey, db.CustomData.Get(SigningKeyKey));
			Assert.IsFalse(DeviceKeyStore.RestoreIfChanged(db));
		}

		[TestMethod]
		public void ClearRemovesRecordsAndSigningKey()
		{
			PwDatabase db = CreateDatabase();

			Assert.IsTrue(DeviceKeyStore.Clear(db));
			Assert.IsTrue(DeviceKeyStore.LoadAll(db).IsEmpty);
			Assert.IsNull(db.CustomData.Get(SigningKeyKey));
		}

		[TestMethod]
		public void CorruptedRecordsAreRejected()
		{
			byte[] records = CreateDatabase().PublicCustomData.GetByteArray(RecordsKey);

			byte[] truncated = new byte[records.Length - 1];
			Array.Copy(records, truncated, truncated.Length);
			byte[] trailing = new byte[records.Length + 1];
			Array.Copy(records, trailing, records.Length);
			byte[] version = (byte[])records.Clone();
			version[0] = 3;
			byte[] recoveryFlag = (byte[])records.Clone();
			recoveryFlag[records.Length - SigningKey.SignatureLength - KeyWrap.SerializedLength - 1] = 2;

			foreach (byte[] data in new[] { truncated, trailing, version, recoveryFlag, new byte[] { 4 } })
				Assert.ThrowsException<InvalidDataException>(() => ReadFromFile(data));
		}

		[TestMethod]
		public void RecordsWithOnlyClassicDevicesKeepVersion4()
		{
			// Plugin versions before portable devices read only v4
			byte[] records = CreateDatabase(DeviceKind.Classic).PublicCustomData.GetByteArray(RecordsKey);

			DeviceRecordSet set = ReadFromFile(records);

			Assert.AreEqual((byte)4, records[0]);
			Assert.AreEqual(DeviceKind.Classic, set.Devices[0].Kind);
			Assert.AreEqual(DeviceKind.Classic, set.Devices[1].Kind);
		}

		[TestMethod]
		public void PortableDevicesAreSavedAsVersion5()
		{
			byte[] records = CreateDatabase(DeviceKind.Portable).PublicCustomData.GetByteArray(RecordsKey);

			DeviceRecordSet set = ReadFromFile(records);

			Assert.AreEqual((byte)5, records[0]);
			Assert.IsTrue(set.VerifySignature());
			Assert.AreEqual(DeviceKind.Classic, set.Devices[0].Kind);
			Assert.AreEqual(DeviceKind.Portable, set.Devices[1].Kind);
			Assert.AreEqual("Portable device", set.Devices[1].Label);
			CollectionAssert.AreEqual(key, set.Devices[1].Wrap.Open(deviceSecret, set.VerificationKey));
		}

		[TestMethod]
		public void ClassicDeviceIsReplacedWithPortableKeepingTheKey()
		{
			PwDatabase db = CreateDatabase(DeviceKind.Classic);
			db.MasterKey = new CompositeKey();
			db.MasterKey.AddUserKey(new KcpCustomKey(FIDO2KeyProvider.ProviderName, key, false));
			byte[] original = db.PublicCustomData.GetByteArray(RecordsKey);
			DeviceRecordSet before = ReadFromFile(original);
			byte[] newSecret = TestData.Random(KeyWrap.KeyLength);
			var created = new PrfResult { CredentialId = TestData.Random(16), PrfSecret = (byte[])newSecret.Clone() };

			FIDO2KeyProvider.ReplaceWithPortable(db, DeviceKeyStore.LoadAll(db), 0, created);

			byte[] records = db.PublicCustomData.GetByteArray(RecordsKey);
			DeviceRecordSet after = ReadFromFile(records);
			Assert.AreEqual((byte)4, original[0]);
			Assert.AreEqual((byte)5, records[0]);
			Assert.IsTrue(after.VerifySignature());
			Assert.AreEqual(2, after.Devices.Count);
			// The new passkey takes the place and the label of the old one and opens the same key
			DeviceRecord replaced = after.Devices[0];
			Assert.AreEqual(DeviceKind.Portable, replaced.Kind);
			Assert.AreEqual(before.Devices[0].Label, replaced.Label);
			CollectionAssert.AreEqual(created.CredentialId, replaced.CredentialId);
			Assert.IsNull(DeviceKeyStore.Find(after.Devices, before.Devices[0].CredentialId));
			CollectionAssert.AreEqual(key, replaced.Wrap.Open(newSecret, after.VerificationKey));
			Assert.ThrowsException<CryptographicException>(() => replaced.Wrap.Open(deviceSecret, after.VerificationKey));
			// The other device and the recovery phrase are untouched
			Assert.AreEqual(DeviceKind.Classic, after.Devices[1].Kind);
			CollectionAssert.AreEqual(before.Devices[1].CredentialId, after.Devices[1].CredentialId);
			CollectionAssert.AreEqual(Bytes(before.Devices[1].Wrap), Bytes(after.Devices[1].Wrap));
			CollectionAssert.AreEqual(Bytes(before.Recovery), Bytes(after.Recovery));
			CollectionAssert.AreEqual(key, after.Recovery.Open(phraseSecret, after.VerificationKey));
		}

		[TestMethod]
		public void OnlyClassicDeviceIsReplacedWithPortable()
		{
			PwDatabase db = CreateDatabase(DeviceKind.Portable);
			db.MasterKey = new CompositeKey();
			db.MasterKey.AddUserKey(new KcpCustomKey(FIDO2KeyProvider.ProviderName, key, false));
			var created = new PrfResult { CredentialId = TestData.Random(16), PrfSecret = TestData.Random(KeyWrap.KeyLength) };

			Assert.ThrowsException<InvalidOperationException>(() => FIDO2KeyProvider.ReplaceWithPortable(db, DeviceKeyStore.LoadAll(db), 1, created));
		}

		[TestMethod]
		public void OnlyPortableDevicesNeedVersion5()
		{
			// Before adding a portable device to such records, the user is asked to update older plugins
			var set = new DeviceRecordSet();
			Assert.IsFalse(DeviceKeyStore.UsesVersion5(set));
			set.Devices.Add(new DeviceRecord { Kind = DeviceKind.Classic });
			Assert.IsFalse(DeviceKeyStore.UsesVersion5(set));
			set.Devices.Add(new DeviceRecord { Kind = DeviceKind.Portable });
			Assert.IsTrue(DeviceKeyStore.UsesVersion5(set));
		}

		[TestMethod]
		public void UnknownDeviceKindIsRejected()
		{
			byte[] records = CreateDatabase(DeviceKind.Portable).PublicCustomData.GetByteArray(RecordsKey);
			records[1 + KeyWrap.PublicKeyLength + 2] = 7; // kind of the first device

			Assert.ThrowsException<InvalidDataException>(() => ReadFromFile(records));
		}

		[TestMethod]
		public void FileWithoutRecordsYieldsEmptySet()
		{
			TestData.WriteKdbxHeader(path, null);
			Assert.IsTrue(DeviceKeyStore.LoadAllFromFile(IOConnectionInfo.FromPath(path)).IsEmpty);

			File.WriteAllBytes(path, TestData.Random(100));
			Assert.IsTrue(DeviceKeyStore.LoadAllFromFile(IOConnectionInfo.FromPath(path)).IsEmpty);
		}

		[TestMethod]
		public void OversizedHeaderFieldIsRejected()
		{
			using (var bw = new BinaryWriter(File.Create(path)))
			{
				bw.Write(0x9AA2D903u);
				bw.Write(0xB54BFB67u);
				bw.Write(0x00040001u);
				bw.Write((byte)12);
				bw.Write(int.MaxValue);
			}

			Assert.ThrowsException<InvalidDataException>(() => DeviceKeyStore.LoadAllFromFile(IOConnectionInfo.FromPath(path)));
		}

		[TestMethod]
		public void TruncatedHeaderIsRejected()
		{
			var publicCustomData = new VariantDictionary();
			publicCustomData.SetByteArray(RecordsKey, TestData.Random(100));
			TestData.WriteKdbxHeader(path, publicCustomData);
			using (FileStream s = File.OpenWrite(path))
				s.SetLength(s.Length - 20); // inside PublicCustomData

			Assert.ThrowsException<InvalidDataException>(() => DeviceKeyStore.LoadAllFromFile(IOConnectionInfo.FromPath(path)));
		}

		/// <summary>
		/// Open database with one classic device and a recovery phrase, as after creation by plugin versions before
		/// portable devices, plus devices of the given kinds
		/// </summary>
		private PwDatabase CreateDatabase(params DeviceKind[] moreDevices)
		{
			var db = new PwDatabase();
			using (SigningKey signingKey = SigningKey.Generate())
			{
				DeviceKeyStore.SetSigningKey(db, signingKey);
				var set = new DeviceRecordSet
				{
					VerificationKey = signingKey.VerificationKey,
					Recovery = KeyWrap.Create(key, phraseSecret, signingKey.VerificationKey)
				};
				set.Devices.Add(new DeviceRecord
				{
					CredentialId = TestData.Random(16),
					Wrap = KeyWrap.Create(key, deviceSecret, signingKey.VerificationKey),
					Label = "Device"
				});
				foreach (DeviceKind kind in moreDevices)
				{
					set.Devices.Add(new DeviceRecord
					{
						Kind = kind,
						CredentialId = TestData.Random(16),
						Wrap = KeyWrap.Create(key, deviceSecret, signingKey.VerificationKey),
						Label = kind + " device"
					});
				}
				DeviceKeyStore.Save(db, set);
			}
			return db;
		}

		private static byte[] Bytes(KeyWrap wrap)
		{
			using (var ms = new MemoryStream())
			using (var bw = new BinaryWriter(ms))
			{
				wrap.Write(bw);
				bw.Flush();
				return ms.ToArray();
			}
		}

		/// <summary>Records as the plugin reads them from a database file before unlocking</summary>
		private DeviceRecordSet ReadFromFile(byte[] records)
		{
			var publicCustomData = new VariantDictionary();
			publicCustomData.SetByteArray(RecordsKey, records);
			TestData.WriteKdbxHeader(path, publicCustomData);
			return DeviceKeyStore.LoadAllFromFile(IOConnectionInfo.FromPath(path));
		}
	}
}
