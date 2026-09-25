using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Device record: database key K wrapped for this device (see <see cref="KeyWrap"/>)
	/// </summary>
	public sealed class DeviceRecord
	{
		public byte[] CredentialId { get; set; }

		public KeyWrap Wrap { get; set; }

		public string Label { get; set; }
	}

	/// <summary>
	/// Stores device records in PublicCustomData of the KDBX 4 outer header.
	/// The header is not encrypted (read before unlocking) but is HMAC-protected, so tampering is detected.
	/// Database key K is random and exists only wrapped for each device and the recovery phrase; the database
	/// cannot be opened without the records. Credential IDs of all records are passed in allowList so that
	/// Windows does not show a credential picker.
	/// </summary>
	public static class DeviceKeyStore
	{
		// IMPORTANT: the key names and record formats are part of the database "format". Change only with a version bump.
		// Devices v1/v2 (XOR wrapping) and recovery v1 are no longer supported.
		private const string CustomDataKey = "KeePassFIDO2.Devices";
		private const byte FormatVersion = 3;
		private const string RecoveryDataKey = "KeePassFIDO2.Recovery";
		private const byte RecoveryFormatVersion = 2;

		// KDBX outer header (KdbxFile constants in KeePassLib are not public)
		private const uint FileSignature1 = 0x9AA2D903;
		private const uint FileSignature2 = 0xB54BFB67;
		private const uint FileVersionCriticalMask = 0xFFFF0000;
		private const uint FileVersion4 = 0x00040000;
		private const byte HeaderEndOfHeader = 0;
		private const byte HeaderPublicCustomData = 12;
		// Outer header fields are bytes/kilobytes; anything larger is a corrupted or forged file
		private const int MaxHeaderFieldSize = 1024 * 1024;

		/// <summary>Records as the plugin last read or wrote them, per open database (see <see cref="RestoreIfChanged"/>)</summary>
		private static readonly ConditionalWeakTable<PwDatabase, Snapshot> snapshots = new ConditionalWeakTable<PwDatabase, Snapshot>();

		private sealed class Snapshot
		{
			public byte[] Devices;
			public byte[] Recovery;
		}

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
			Remember(db);
		}

		/// <summary>Key wrapped for the recovery phrase; null if there is no phrase</summary>
		public static KeyWrap LoadRecovery(PwDatabase db)
		{
			return ParseRecovery(db.PublicCustomData.GetByteArray(RecoveryDataKey));
		}

		/// <summary>Writes (null removes) the recovery phrase record and marks the database modified</summary>
		public static void SaveRecovery(PwDatabase db, KeyWrap wrap)
		{
			if (wrap == null)
				db.PublicCustomData.Remove(RecoveryDataKey);
			else
			{
				using (var ms = new MemoryStream())
				using (var bw = new BinaryWriter(ms))
				{
					bw.Write(RecoveryFormatVersion);
					wrap.Write(bw);
					bw.Flush();
					db.PublicCustomData.SetByteArray(RecoveryDataKey, ms.ToArray());
				}
			}
			db.Modified = true;
			Remember(db);
		}

		/// <summary>
		/// Removes all records and the recovery phrase (after a master key change they wrap an invalid K)
		/// </summary>
		public static bool Clear(PwDatabase db)
		{
			bool devices = db.PublicCustomData.Remove(CustomDataKey);
			bool recovery = db.PublicCustomData.Remove(RecoveryDataKey);
			Remember(db);
			return devices || recovery;
		}

		/// <summary>Remembers the records of the database as valid (on opening and after each write by the plugin)</summary>
		public static void Remember(PwDatabase db)
		{
			if (db == null) return;
			snapshots.Remove(db);
			snapshots.Add(db, new Snapshot
			{
				Devices = CloneOrNull(db.PublicCustomData.GetByteArray(CustomDataKey)),
				Recovery = CloneOrNull(db.PublicCustomData.GetByteArray(RecoveryDataKey))
			});
		}

		/// <summary>
		/// Called before saving. Only the plugin changes its records, but merging another database into this one
		/// (File → Import, Synchronize) copies that database's PublicCustomData — records that wrap a different key.
		/// Saving them would make the database impossible to open, so the remembered records are put back.
		/// </summary>
		/// <returns>true if the records were restored</returns>
		public static bool RestoreIfChanged(PwDatabase db)
		{
			Snapshot snapshot;
			if (db == null || !snapshots.TryGetValue(db, out snapshot)) return false;

			bool devices = Restore(db, CustomDataKey, snapshot.Devices);
			bool recovery = Restore(db, RecoveryDataKey, snapshot.Recovery);
			return devices || recovery;
		}

		private static bool Restore(PwDatabase db, string key, byte[] expected)
		{
			byte[] current = db.PublicCustomData.GetByteArray(key);
			if (current == null && expected == null) return false;
			if (current != null && expected != null && MemUtil.ArraysEqual(current, expected)) return false;

			if (expected == null)
				db.PublicCustomData.Remove(key);
			else
				db.PublicCustomData.SetByteArray(key, (byte[])expected.Clone());
			return true;
		}

		private static byte[] CloneOrNull(byte[] data)
		{
			return data == null ? null : (byte[])data.Clone();
		}

		/// <summary>Device records from the database file before unlocking; no records — empty list</summary>
		public static List<DeviceRecord> LoadFromFile(IOConnectionInfo ioc)
		{
			return Parse(ReadPublicCustomData(ioc)?.GetByteArray(CustomDataKey));
		}

		/// <summary>Recovery phrase record from the database file before unlocking; null if there is no phrase</summary>
		public static KeyWrap LoadRecoveryFromFile(IOConnectionInfo ioc)
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
					r.Wrap.Write(bw);
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

			try
			{
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
							Wrap = KeyWrap.Read(br),
							Label = Encoding.UTF8.GetString(ReadBlock(br))
						};
						if (record.CredentialId.Length == 0)
							throw new InvalidDataException(Strings.CorruptedDeviceRecord);
						records.Add(record);
					}
				}
			}
			catch (EndOfStreamException)
			{
				throw new InvalidDataException(Strings.CorruptedDeviceRecord);
			}
			return records;
		}

		private static KeyWrap ParseRecovery(byte[] data)
		{
			if (data == null || data.Length == 0) return null;
			if (data[0] != RecoveryFormatVersion)
				throw new InvalidDataException(string.Format(Strings.UnsupportedRecoveryRecordVersion, data[0]));
			if (data.Length != KeyWrap.SerializedLength + 1)
				throw new InvalidDataException(Strings.CorruptedRecoveryRecord);

			using (var br = new BinaryReader(new MemoryStream(data, 1, data.Length - 1, false)))
				return KeyWrap.Read(br);
		}

		private static void WriteBlock(BinaryWriter bw, byte[] block)
		{
			bw.Write((ushort)block.Length);
			bw.Write(block);
		}

		private static byte[] ReadBlock(BinaryReader br)
		{
			int length = br.ReadUInt16();
			byte[] block = br.ReadBytes(length);
			if (block.Length != length) throw new EndOfStreamException();
			return block;
		}
	}
}
