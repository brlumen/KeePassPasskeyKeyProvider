using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
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
	/// Everything stored in the database header: verification key, device records and the recovery phrase wrap
	/// </summary>
	public sealed class DeviceRecordSet
	{
		/// <summary>Database verification key VK (see <see cref="SigningKey"/>); null if there are no records</summary>
		public byte[] VerificationKey { get; set; }

		public List<DeviceRecord> Devices { get; } = new List<DeviceRecord>();

		/// <summary>Key wrapped for the recovery phrase; null if there is no phrase</summary>
		public KeyWrap Recovery { get; set; }

		public bool IsEmpty => Devices.Count == 0 && Recovery == null;

		internal byte[] SignedData { get; set; }

		internal byte[] Signature { get; set; }

		/// <summary>
		/// Checks the signature of records read from a file. Meaningful only together with the owner tag check
		/// (<see cref="KeyWrap.Open"/>), which binds VK to the owner's secret.
		/// </summary>
		public bool VerifySignature()
		{
			return VerificationKey != null && SignedData != null && SigningKey.Verify(VerificationKey, SignedData, Signature);
		}
	}

	/// <summary>
	/// Stores device records in PublicCustomData of the KDBX 4 outer header. The header is not encrypted (it is read
	/// before unlocking), and anyone with write access to the file can replace it, so the plugin authenticates the
	/// records itself:
	/// - each database has an ECDSA key pair; the verification key VK is stored with the records, the signing key SK
	///   in the encrypted part (CustomData), and every write signs the records with SK;
	/// - each wrap carries an owner tag that binds the owner's secret to VK (see <see cref="KeyWrap"/>).
	/// On unlocking, the device (or phrase) secret must match the tag for VK and the signature must verify with VK.
	/// So without the database key K nobody can build a database that the user's device silently opens: a copied
	/// wrap is bound to the victim's VK, and signing for that VK requires SK from inside the database.
	/// Not protected: anyone who ever had K (including a removed device or phrase with an old copy of the file)
	/// can extract SK from that copy and still forge records, because rotation does not change SK (the tags of the
	/// remaining owners are bound to VK, and their secrets are not available to re-tag them).
	/// Database key K is random and exists only wrapped for each device and the recovery phrase; the database
	/// cannot be opened without the records. Credential IDs of all records are passed in allowList so that
	/// Windows does not show a credential picker.
	/// </summary>
	public static class DeviceKeyStore
	{
		// IMPORTANT: the key names and record formats are part of the database "format". Change only with a version bump.
		// Earlier versions (devices v1–v3, the separate "KeePassFIDO2.Recovery" record) are no longer supported.
		// v4 layout (integers little-endian):
		//   byte version = 4
		//   byte[65] VK (0x04 ‖ X ‖ Y, P‑256)
		//   ushort device count; per device: ushort length + credential ID, KeyWrap, ushort length + UTF‑8 label
		//   byte recovery flag (0/1); if 1: KeyWrap
		//   byte[64] ECDSA P‑256 / SHA‑256 signature (r ‖ s) over all preceding bytes
		// KeyWrap: Q (65) ‖ d ⊕ S (32) ‖ ephemeral public key (65) ‖ wrapped K (32) ‖ owner tag (32)
		private const string CustomDataKey = "KeePassFIDO2.Devices";
		private const byte FormatVersion = 4;
		// Private scalar of SK (base64) in the encrypted CustomData
		private const string SigningKeyDataKey = "KeePassFIDO2.SigningKey";

		// KDBX outer header (KdbxFile constants in KeePassLib are not public)
		private const uint FileSignature1 = 0x9AA2D903;
		private const uint FileSignature2 = 0xB54BFB67;
		private const uint FileVersionCriticalMask = 0xFFFF0000;
		private const uint FileVersion4 = 0x00040000;
		private const byte HeaderEndOfHeader = 0;
		private const byte HeaderPublicCustomData = 12;
		// Outer header fields are bytes/kilobytes; anything larger is a corrupted or forged file
		private const int MaxHeaderFieldSize = 1024 * 1024;

		/// <summary>Records and signing key as the plugin last read or wrote them, per open database (see <see cref="RestoreIfChanged"/>)</summary>
		private static readonly ConditionalWeakTable<PwDatabase, Snapshot> snapshots = new ConditionalWeakTable<PwDatabase, Snapshot>();

		private sealed class Snapshot
		{
			public byte[] Records;
			public string SigningKey;
		}

		/// <summary>Records of the open database (first restored if a merge replaced them); no records — empty set</summary>
		public static DeviceRecordSet LoadAll(PwDatabase db)
		{
			RestoreIfChanged(db);
			return Parse(db.PublicCustomData.GetByteArray(CustomDataKey));
		}

		public static List<DeviceRecord> Load(PwDatabase db)
		{
			return LoadAll(db).Devices;
		}

		/// <summary>
		/// Signs the records with the database signing key and writes them to the open database, marking it modified.
		/// KeePass upgrades the format to KDBX 4 itself.
		/// </summary>
		/// <exception cref="InvalidOperationException">The database has no signing key matching the records</exception>
		public static void Save(PwDatabase db, DeviceRecordSet set)
		{
			if (set.IsEmpty)
			{
				RestoreIfChanged(db);
				db.PublicCustomData.Remove(CustomDataKey);
			}
			else
			{
				using (SigningKey signingKey = LoadSigningKey(db, set.VerificationKey))
				{
					if (signingKey == null)
						throw new InvalidOperationException(Strings.SigningKeyInvalid);
					db.PublicCustomData.SetByteArray(CustomDataKey, Serialize(set, signingKey));
				}
			}
			db.Modified = true;
			Remember(db);
		}

		/// <summary>
		/// Signing key of the open database matching the verification key; null if it is missing or does not match
		/// </summary>
		public static SigningKey LoadSigningKey(PwDatabase db, byte[] verificationKey)
		{
			RestoreIfChanged(db);
			string stored = db.CustomData.Get(SigningKeyDataKey);
			if (string.IsNullOrEmpty(stored) || verificationKey == null) return null;

			byte[] privateKey;
			try { privateKey = Convert.FromBase64String(stored); }
			catch (FormatException) { return null; }

			if (privateKey.Length != KeyWrap.KeyLength)
			{
				MemUtil.ZeroByteArray(privateKey);
				return null;
			}
			try { return SigningKey.Import(privateKey, verificationKey); }
			catch (CryptographicException) { return null; } // Import zeroes the key on failure
		}

		/// <summary>
		/// Replaces the signing key of the open database (new database or master key change without keeping devices).
		/// The records must be written afterwards with its verification key.
		/// </summary>
		public static void SetSigningKey(PwDatabase db, SigningKey signingKey)
		{
			RestoreIfChanged(db);
			byte[] privateKey = signingKey.ExportPrivateKey();
			try
			{
				// A managed string cannot be wiped; it is stored in the encrypted part of the database anyway
				db.CustomData.Set(SigningKeyDataKey, Convert.ToBase64String(privateKey));
			}
			finally
			{
				MemUtil.ZeroByteArray(privateKey);
			}
			db.Modified = true;
			Remember(db);
		}

		/// <summary>
		/// Removes all records, the recovery phrase and the signing key (after a master key change they wrap an invalid K)
		/// </summary>
		public static bool Clear(PwDatabase db)
		{
			bool records = db.PublicCustomData.Remove(CustomDataKey);
			bool signingKey = db.CustomData.Remove(SigningKeyDataKey);
			Remember(db);
			return records || signingKey;
		}

		/// <summary>Remembers the records of the database as valid (on opening and after each write by the plugin)</summary>
		public static void Remember(PwDatabase db)
		{
			if (db == null) return;
			snapshots.Remove(db);
			snapshots.Add(db, new Snapshot
			{
				Records = CloneOrNull(db.PublicCustomData.GetByteArray(CustomDataKey)),
				SigningKey = db.CustomData.Get(SigningKeyDataKey)
			});
		}

		/// <summary>
		/// Called before saving and before every read of the open database. Only the plugin changes its records, but
		/// merging another database into this one (File → Import, Synchronize) copies that database's PublicCustomData
		/// and CustomData: records that wrap a different key for foreign owners, and a foreign signing key.
		/// Using or saving them would seal K for the foreign owners and lock out the own devices,
		/// so the remembered records and signing key are put back.
		/// </summary>
		/// <returns>true if something was restored</returns>
		public static bool RestoreIfChanged(PwDatabase db)
		{
			Snapshot snapshot;
			if (db == null || !snapshots.TryGetValue(db, out snapshot)) return false;

			bool records = RestoreRecords(db, snapshot.Records);
			bool signingKey = RestoreSigningKey(db, snapshot.SigningKey);
			return records || signingKey;
		}

		private static bool RestoreRecords(PwDatabase db, byte[] expected)
		{
			byte[] current = db.PublicCustomData.GetByteArray(CustomDataKey);
			if (current == null && expected == null) return false;
			if (current != null && expected != null && MemUtil.ArraysEqual(current, expected)) return false;

			if (expected == null)
				db.PublicCustomData.Remove(CustomDataKey);
			else
				db.PublicCustomData.SetByteArray(CustomDataKey, (byte[])expected.Clone());
			return true;
		}

		private static bool RestoreSigningKey(PwDatabase db, string expected)
		{
			if (string.Equals(db.CustomData.Get(SigningKeyDataKey), expected, StringComparison.Ordinal)) return false;

			if (expected == null)
				db.CustomData.Remove(SigningKeyDataKey);
			else
				db.CustomData.Set(SigningKeyDataKey, expected);
			return true;
		}

		private static byte[] CloneOrNull(byte[] data)
		{
			return data == null ? null : (byte[])data.Clone();
		}

		/// <summary>Records from the database file before unlocking (signature not checked yet); no records — empty set</summary>
		public static DeviceRecordSet LoadAllFromFile(IOConnectionInfo ioc)
		{
			return Parse(ReadPublicCustomData(ioc)?.GetByteArray(CustomDataKey));
		}

		/// <summary>Device records from the database file before unlocking; no records — empty list</summary>
		public static List<DeviceRecord> LoadFromFile(IOConnectionInfo ioc)
		{
			return LoadAllFromFile(ioc).Devices;
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

		private static byte[] Serialize(DeviceRecordSet set, SigningKey signingKey)
		{
			using (var ms = new MemoryStream())
			using (var bw = new BinaryWriter(ms))
			{
				bw.Write(FormatVersion);
				bw.Write(set.VerificationKey);
				bw.Write(checked((ushort)set.Devices.Count));
				foreach (DeviceRecord r in set.Devices)
				{
					WriteBlock(bw, r.CredentialId);
					r.Wrap.Write(bw);
					WriteBlock(bw, Encoding.UTF8.GetBytes(r.Label ?? string.Empty));
				}
				bw.Write((byte)(set.Recovery != null ? 1 : 0));
				set.Recovery?.Write(bw);
				bw.Flush();

				byte[] signature = signingKey.Sign(ms.ToArray());
				if (signature.Length != SigningKey.SignatureLength)
					throw new CryptographicException("Unexpected signature format");
				bw.Write(signature);
				bw.Flush();
				return ms.ToArray();
			}
		}

		private static DeviceRecordSet Parse(byte[] data)
		{
			var set = new DeviceRecordSet();
			if (data == null || data.Length == 0) return set;

			try
			{
				using (var ms = new MemoryStream(data, false))
				using (var br = new BinaryReader(ms))
				{
					byte version = br.ReadByte();
					if (version != FormatVersion)
						throw new InvalidDataException(string.Format(Strings.UnsupportedDeviceRecordsVersion, version));

					set.VerificationKey = ReadExact(br, KeyWrap.PublicKeyLength);
					if (set.VerificationKey[0] != 0x04)
						throw new InvalidDataException(Strings.CorruptedDeviceRecord);

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
						set.Devices.Add(record);
					}

					switch (br.ReadByte())
					{
						case 0: break;
						case 1: set.Recovery = KeyWrap.Read(br); break;
						default: throw new InvalidDataException(Strings.CorruptedDeviceRecord);
					}

					int signedLength = (int)ms.Position;
					set.Signature = ReadExact(br, SigningKey.SignatureLength);
					if (ms.Position != data.Length)
						throw new InvalidDataException(Strings.CorruptedDeviceRecord);
					set.SignedData = new byte[signedLength];
					Array.Copy(data, set.SignedData, signedLength);
				}
			}
			catch (EndOfStreamException)
			{
				throw new InvalidDataException(Strings.CorruptedDeviceRecord);
			}
			return set;
		}

		private static void WriteBlock(BinaryWriter bw, byte[] block)
		{
			bw.Write((ushort)block.Length);
			bw.Write(block);
		}

		private static byte[] ReadExact(BinaryReader br, int length)
		{
			byte[] data = br.ReadBytes(length);
			if (data.Length != length) throw new EndOfStreamException();
			return data;
		}

		private static byte[] ReadBlock(BinaryReader br)
		{
			int length = br.ReadUInt16();
			return ReadExact(br, length);
		}
	}
}
