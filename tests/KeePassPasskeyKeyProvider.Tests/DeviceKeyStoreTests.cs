using System;
using System.IO;
using System.Security.Cryptography;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Serialization;
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

		/// <summary>Open database with one device and a recovery phrase, as after creation by the plugin</summary>
		private PwDatabase CreateDatabase()
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
				DeviceKeyStore.Save(db, set);
			}
			return db;
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
