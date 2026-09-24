using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace KeePassPasskey
{
	/// <summary>
	/// Запись об устройстве: ключ базы K, «обёрнутый» PRF‑секретом этого устройства
	/// </summary>
	public sealed class DeviceRecord
	{
		public byte[] CredentialId { get; set; }

		/// <summary>K ⊕ PRF (32 байта)</summary>
		public byte[] WrappedKey { get; set; }

		public string Label { get; set; }
	}

	/// <summary>
	/// Хранение записей устройств в PublicCustomData внешнего заголовка KDBX 4.
	/// Заголовок не зашифрован (читается до разблокировки), но защищён HMAC — подмена обнаружится.
	/// Ключ базы K случаен и существует только в обёртках K ⊕ PRF_i — одноразовый блокнот: PRF_i случаен,
	/// той же длины и нигде больше не используется. Без записей базу открыть нельзя.
	/// Смена K (ротация при удалении устройства) — перешифрование обёрток без участия аутентификаторов:
	/// K_new ⊕ PRF_i = (K_old ⊕ PRF_i) ⊕ K_old ⊕ K_new.
	/// Credential ID всех записей передаются в allowList, чтобы Windows не показывал выбор credential.
	/// Фраза восстановления хранится отдельно той же обёрткой K ⊕ R (см. <see cref="RecoveryPhrase"/>).
	/// </summary>
	public static class DeviceKeyStore
	{
		// ВАЖНО: имя ключа и формат записей — часть «формата» базы. Менять только с bump версии.
		// v1 (пустой WrappedKey = «PRF основного устройства и есть K») больше не поддерживается.
		private const string CustomDataKey = "KeePassFIDO2.Devices";
		private const byte FormatVersion = 2;
		private const string RecoveryDataKey = "KeePassFIDO2.Recovery";
		private const byte RecoveryFormatVersion = 1;
		public const int KeyLength = 32;

		// Внешний заголовок KDBX (константы KdbxFile в KeePassLib не публичны)
		private const uint FileSignature1 = 0x9AA2D903;
		private const uint FileSignature2 = 0xB54BFB67;
		private const uint FileVersionCriticalMask = 0xFFFF0000;
		private const uint FileVersion4 = 0x00040000;
		private const byte HeaderEndOfHeader = 0;
		private const byte HeaderPublicCustomData = 12;
		// Поля внешнего заголовка — байты/килобайты; больше — повреждённый или подделанный файл
		private const int MaxHeaderFieldSize = 1024 * 1024;

		public static List<DeviceRecord> Load(PwDatabase db)
		{
			return Parse(db.PublicCustomData.GetByteArray(CustomDataKey));
		}

		/// <summary>
		/// Записывает записи в открытую базу и помечает её изменённой. KeePass сам поднимет формат до KDBX 4.
		/// </summary>
		public static void Save(PwDatabase db, List<DeviceRecord> records)
		{
			if (records.Count == 0)
				db.PublicCustomData.Remove(CustomDataKey);
			else
				db.PublicCustomData.SetByteArray(CustomDataKey, Serialize(records));
			db.Modified = true;
		}

		/// <summary>Обёртка ключа фразой восстановления K ⊕ R; null, если фразы нет</summary>
		public static byte[] LoadRecovery(PwDatabase db)
		{
			return ParseRecovery(db.PublicCustomData.GetByteArray(RecoveryDataKey));
		}

		/// <summary>Записывает (null — удаляет) обёртку фразы восстановления и помечает базу изменённой</summary>
		public static void SaveRecovery(PwDatabase db, byte[] wrappedKey)
		{
			if (wrappedKey == null)
				db.PublicCustomData.Remove(RecoveryDataKey);
			else
			{
				CheckLength(wrappedKey, "обёрнутого ключа");
				byte[] data = new byte[KeyLength + 1];
				data[0] = RecoveryFormatVersion;
				Array.Copy(wrappedKey, 0, data, 1, KeyLength);
				db.PublicCustomData.SetByteArray(RecoveryDataKey, data);
			}
			db.Modified = true;
		}

		/// <summary>
		/// Удаляет все записи и фразу восстановления (после смены мастер‑ключа они шифруют уже недействительный K)
		/// </summary>
		public static bool Clear(PwDatabase db)
		{
			bool devices = db.PublicCustomData.Remove(CustomDataKey);
			bool recovery = db.PublicCustomData.Remove(RecoveryDataKey);
			return devices || recovery;
		}

		/// <summary>Записи устройств из файла базы до её разблокировки; нет записей — пустой список</summary>
		public static List<DeviceRecord> LoadFromFile(IOConnectionInfo ioc)
		{
			return Parse(ReadPublicCustomData(ioc)?.GetByteArray(CustomDataKey));
		}

		/// <summary>Обёртка фразы восстановления из файла базы до её разблокировки; null, если фразы нет</summary>
		public static byte[] LoadRecoveryFromFile(IOConnectionInfo ioc)
		{
			return ParseRecovery(ReadPublicCustomData(ioc)?.GetByteArray(RecoveryDataKey));
		}

		/// <summary>
		/// PublicCustomData из файла базы. KeePass не даёт API «прочитать только заголовок», поэтому
		/// внешний заголовок (TLV) разбирается самостоятельно. KDBX 3.x и файлы без PublicCustomData дают null.
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
					if (size < 0 || size > MaxHeaderFieldSize) throw new InvalidDataException("Повреждён заголовок KDBX");
					byte[] data = br.ReadBytes(size);
					if (data.Length != size) throw new InvalidDataException("Повреждён заголовок KDBX");

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

		/// <summary>Credential ID всех записей для allowList</summary>
		public static List<byte[]> GetAllowList(List<DeviceRecord> records)
		{
			return records.ConvertAll(r => r.CredentialId);
		}

		/// <summary>K ⊕ PRF — и шифрование, и расшифровка</summary>
		public static byte[] Wrap(byte[] key, byte[] prf)
		{
			CheckLength(key, "ключа");
			CheckLength(prf, "PRF‑секрета");

			byte[] result = new byte[KeyLength];
			for (int i = 0; i < KeyLength; i++)
				result[i] = (byte)(key[i] ^ prf[i]);
			return result;
		}

		/// <summary>
		/// Перешифровывает обёртки со старого ключа базы на новый (на месте).
		/// PRF_i в память не попадает: обёртка меняется за один проход XOR.
		/// </summary>
		public static void Rewrap(IEnumerable<DeviceRecord> records, byte[] oldKey, byte[] newKey)
		{
			foreach (DeviceRecord r in records)
				Rewrap(r.WrappedKey, oldKey, newKey);
		}

		/// <summary>Перешифровывает одну обёртку (устройства или фразы) со старого ключа на новый (на месте)</summary>
		public static void Rewrap(byte[] wrappedKey, byte[] oldKey, byte[] newKey)
		{
			CheckLength(oldKey, "старого ключа");
			CheckLength(newKey, "нового ключа");
			CheckLength(wrappedKey, "обёрнутого ключа");

			for (int i = 0; i < KeyLength; i++)
				wrappedKey[i] ^= (byte)(oldKey[i] ^ newKey[i]);
		}

		private static void CheckLength(byte[] data, string what)
		{
			if (data == null || data.Length != KeyLength)
				throw new ArgumentException($"Ожидается {KeyLength} байт {what}");
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
					throw new InvalidDataException($"Неподдерживаемая версия записей устройств: {version}");

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
						throw new InvalidDataException("Повреждена запись устройства в заголовке базы");
					records.Add(record);
				}
			}
			return records;
		}

		private static byte[] ParseRecovery(byte[] data)
		{
			if (data == null || data.Length == 0) return null;
			if (data[0] != RecoveryFormatVersion)
				throw new InvalidDataException($"Неподдерживаемая версия записи фразы восстановления: {data[0]}");
			if (data.Length != KeyLength + 1)
				throw new InvalidDataException("Повреждена запись фразы восстановления в заголовке базы");

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
