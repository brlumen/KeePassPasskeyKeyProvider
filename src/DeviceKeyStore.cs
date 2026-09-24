using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Device record: database key K "wrapped" with this device's PRF secret
	/// </summary>
	public sealed class DeviceRecord
	{
		public byte[] CredentialId { get; set; }

		/// <summary>K ⊕ PRF (32 bytes)</summary>
		public byte[] WrappedKey { get; set; }

		public string Label { get; set; }
	}

	/// <summary>
	/// Stores device records in PublicCustomData of the KDBX 4 outer header.
	/// The header is not encrypted (read before unlocking) but is HMAC-protected, so tampering is detected.
	/// Database key K is random and exists only in wrapped keys K ⊕ PRF_i — a one-time pad: PRF_i is random,
	/// of the same length and used nowhere else. The database cannot be opened without the records.
	/// Changing K (rotation on device removal) re-wraps keys without authenticators:
	/// K_new ⊕ PRF_i = (K_old ⊕ PRF_i) ⊕ K_old ⊕ K_new.
	/// Credential IDs of all records are passed in allowList so that Windows does not show a credential picker.
	/// The recovery phrase is stored separately with the same wrapping K ⊕ R (see <see cref="RecoveryPhrase"/>).
	/// </summary>
	public static class DeviceKeyStore
	{
		// IMPORTANT: the key name and record format are part of the database "format". Change only with a version bump.
		// v1 (empty WrappedKey = "the main device's PRF is K") is no longer supported.
		private const string CustomDataKey = "KeePassFIDO2.Devices";
		private const byte FormatVersion = 2;
		private const string RecoveryDataKey = "KeePassFIDO2.Recovery";
		private const byte RecoveryFormatVersion = 1;
		public const int KeyLength = 32;

		// KDBX outer header (KdbxFile constants in KeePassLib are not public)
		private const uint FileSignature1 = 0x9AA2D903;
		private const uint FileSignature2 = 0xB54BFB67;
		private const uint FileVersionCriticalMask = 0xFFFF0000;
		private const uint FileVersion4 = 0x00040000;
		private const byte HeaderEndOfHeader = 0;
		private const byte HeaderPublicCustomData = 12;
		// Outer header fields are bytes/kilobytes; anything larger is a corrupted or forged file
		private const int MaxHeaderFieldSize = 1024 * 1024;

		public static List<DeviceRecord> Load(PwDatabase db)
		{
			return Parse(db.PublicCustomData.GetByteArray(CustomDataKey));
		}

		/// <summary>
		/// Writes records to the open database and marks it modified. KeePass upgrades the format to KDBX 4 itself.
		/// </summary>
		public static void Save(PwDatabase db, List<DeviceRecord> records)
		{
			if (records.Count == 0)
				db.PublicCustomData.Remove(CustomDataKey);
			else
				db.PublicCustomData.SetByteArray(CustomDataKey, Serialize(records));
			db.Modified = true;
		}

		/// <summary>Key wrapped with the recovery phrase K ⊕ R; null if there is no phrase</summary>
		public static byte[] LoadRecovery(PwDatabase db)
		{
			return ParseRecovery(db.PublicCustomData.GetByteArray(RecoveryDataKey));
		}

		/// <summary>Writes (null removes) the recovery phrase wrapped key and marks the database modified</summary>
		public static void SaveRecovery(PwDatabase db, byte[] wrappedKey)
		{
			if (wrappedKey == null)
				db.PublicCustomData.Remove(RecoveryDataKey);
			else
			{
				CheckLength(wrappedKey, "wrapped key");
				byte[] data = new byte[KeyLength + 1];
				data[0] = RecoveryFormatVersion;
				Array.Copy(wrappedKey, 0, data, 1, KeyLength);
				db.PublicCustomData.SetByteArray(RecoveryDataKey, data);
			}
			db.Modified = true;
		}

		/// <summary>
		/// Removes all records and the recovery phrase (after a master key change they wrap an invalid K)
		/// </summary>
		public static bool Clear(PwDatabase db)
		{
			bool devices = db.PublicCustomData.Remove(CustomDataKey);
			bool recovery = db.PublicCustomData.Remove(RecoveryDataKey);
			return devices || recovery;
		}

		/// <summary>Device records from the database file before unlocking; no records — empty list</summary>
		public static List<DeviceRecord> LoadFromFile(IOConnectionInfo ioc)
		{
			return Parse(ReadPublicCustomData(ioc)?.GetByteArray(CustomDataKey));
		}

		/// <summary>Recovery phrase wrapped key from the database file before unlocking; null if there is no phrase</summary>
		public static byte[] LoadRecoveryFromFile(IOConnectionInfo ioc)
		{
			return ParseRecovery(ReadPublicCustomData(ioc)?.GetByteArray(RecoveryDataKey));
		}

		/// <summary>
		/// PublicCustomData from the database file. KeePass has no "read header only" API, so
		/// the outer header (TLV) is parsed manually. KDBX 3.x and files without PublicCustomData yield null.
		/// </summary>
		private static VariantDictionary ReadPublicCustomData(IOConnectionInfo ioc)
		{
			using (Stream s = IOConnection.OpenRead(ioc))
			using (var br = new BinaryReader(s))
			{
				if (br.ReadUInt32() != FileSignature1 || br.ReadUInt32() != FileSignature2)
					return null;

				bool kdbx4 = (br.ReadUInt32() & FileVersionCriticalMask) >= FileVersion4;
				while (true)
				{
					byte id = br.ReadByte();
					int size = kdbx4 ? br.ReadInt32() : br.ReadUInt16();
					if (size < 0 || size > MaxHeaderFieldSize) throw new InvalidDataException(Strings.CorruptedKdbxHeader);
					byte[] data = br.ReadBytes(size);
					if (data.Length != size) throw new InvalidDataException(Strings.CorruptedKdbxHeader);

					if (id == HeaderEndOfHeader)
						return null;
					if (id == HeaderPublicCustomData)
						return VariantDictionary.Deserialize(data);
				}
			}
		}

		public static DeviceRecord Find(List<DeviceRecord> records, byte[] credentialId)
		{
			return records.Find(r => MemUtil.ArraysEqual(r.CredentialId, credentialId));
		}

		/// <summary>Credential IDs of all records for allowList</summary>
		public static List<byte[]> GetAllowList(List<DeviceRecord> records)
		{
			return records.ConvertAll(r => r.CredentialId);
		}

		/// <summary>K ⊕ PRF — both encryption and decryption</summary>
		public static byte[] Wrap(byte[] key, byte[] prf)
		{
			CheckLength(key, "key");
			CheckLength(prf, "PRF secret");

			byte[] result = new byte[KeyLength];
			for (int i = 0; i < KeyLength; i++)
				result[i] = (byte)(key[i] ^ prf[i]);
			return result;
		}

		/// <summary>
		/// Re-wraps keys from the old database key to the new one (in place).
		/// PRF_i never enters memory: the wrapped key changes in a single XOR pass.
		/// </summary>
		public static void Rewrap(IEnumerable<DeviceRecord> records, byte[] oldKey, byte[] newKey)
		{
			foreach (DeviceRecord r in records)
				Rewrap(r.WrappedKey, oldKey, newKey);
		}

		/// <summary>Re-wraps one wrapped key (device or phrase) from the old key to the new one (in place)</summary>
		public static void Rewrap(byte[] wrappedKey, byte[] oldKey, byte[] newKey)
		{
			CheckLength(oldKey, "old key");
			CheckLength(newKey, "new key");
			CheckLength(wrappedKey, "wrapped key");

			for (int i = 0; i < KeyLength; i++)
				wrappedKey[i] ^= (byte)(oldKey[i] ^ newKey[i]);
		}

		private static void CheckLength(byte[] data, string what)
		{
			if (data == null || data.Length != KeyLength)
				throw new ArgumentException($"Expected {KeyLength} bytes of {what}");
		}

		private static byte[] Serialize(List<DeviceRecord> records)
		{
			using (var ms = new MemoryStream())
			using (var bw = new BinaryWriter(ms))
			{
				bw.Write(FormatVersion);
				bw.Write((ushort)records.Count);
				foreach (DeviceRecord r in records)
				{
					WriteBlock(bw, r.CredentialId);
					WriteBlock(bw, r.WrappedKey);
					WriteBlock(bw, Encoding.UTF8.GetBytes(r.Label ?? string.Empty));
				}
				bw.Flush();
				return ms.ToArray();
			}
		}

		private static List<DeviceRecord> Parse(byte[] data)
		{
			var records = new List<DeviceRecord>();
			if (data == null || data.Length == 0) return records;

			using (var br = new BinaryReader(new MemoryStream(data, false)))
			{
				byte version = br.ReadByte();
				if (version != FormatVersion)
					throw new InvalidDataException(string.Format(Strings.UnsupportedDeviceRecordsVersion, version));

				int count = br.ReadUInt16();
				for (int i = 0; i < count; i++)
				{
					var record = new DeviceRecord
					{
						CredentialId = ReadBlock(br),
						WrappedKey = ReadBlock(br),
						Label = Encoding.UTF8.GetString(ReadBlock(br))
					};
					if (record.CredentialId.Length == 0 || record.WrappedKey.Length != KeyLength)
						throw new InvalidDataException(Strings.CorruptedDeviceRecord);
					records.Add(record);
				}
			}
			return records;
		}

		private static byte[] ParseRecovery(byte[] data)
		{
			if (data == null || data.Length == 0) return null;
			if (data[0] != RecoveryFormatVersion)
				throw new InvalidDataException(string.Format(Strings.UnsupportedRecoveryRecordVersion, data[0]));
			if (data.Length != KeyLength + 1)
				throw new InvalidDataException(Strings.CorruptedRecoveryRecord);

			byte[] wrappedKey = new byte[KeyLength];
			Array.Copy(data, 1, wrappedKey, 0, KeyLength);
			return wrappedKey;
		}

		private static void WriteBlock(BinaryWriter bw, byte[] block)
		{
			bw.Write((ushort)block.Length);
			bw.Write(block);
		}

		private static byte[] ReadBlock(BinaryReader br)
		{
			return br.ReadBytes(br.ReadUInt16());
		}
	}
}
