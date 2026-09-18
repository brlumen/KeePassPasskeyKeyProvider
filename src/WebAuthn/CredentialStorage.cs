using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KeePassFIDO2.WebAuthn
{
	/// <summary>
	/// Класс для сохранения и загрузки Credential ID
	/// Credential ID сохраняется в файл рядом с базой данных KeePass
	/// </summary>
	public class CredentialStorage
	{
		private const string FILE_EXTENSION = ".fido2";
		private const string MAGIC_HEADER = "KeePassFIDO2v1";

		/// <summary>
		/// Сохраняет credential ID в файл
		/// </summary>
		/// <param name="databasePath">Путь к базе данных KeePass</param>
		/// <param name="credentialId">Credential ID для сохранения</param>
		/// <param name="userId">User ID, использованный при создании credential</param>
		public static void SaveCredentialId(string databasePath, byte[] credentialId, byte[] userId)
		{
			if (string.IsNullOrEmpty(databasePath))
			{
				throw new ArgumentException("Database path cannot be null or empty", nameof(databasePath));
			}

			if (credentialId == null || credentialId.Length == 0)
			{
				throw new ArgumentException("Credential ID cannot be null or empty", nameof(credentialId));
			}

			if (userId == null || userId.Length == 0)
			{
				throw new ArgumentException("User ID cannot be null or empty", nameof(userId));
			}

			string credentialFilePath = GetCredentialFilePath(databasePath);

			// Сначала подготовим все данные в памяти
			byte[] header = Encoding.UTF8.GetBytes(MAGIC_HEADER);
			long timestamp = DateTime.UtcNow.ToBinary();

			// Вычисляем размер буфера
			int bufferSize = 
				sizeof(int) +              // header.Length
				header.Length +            // header
				sizeof(ushort) +           // version
				sizeof(ushort) +           // userId.Length
				userId.Length +            // userId
				sizeof(ushort) +           // credentialId.Length
				credentialId.Length +      // credentialId
				sizeof(long);              // timestamp

			// Записываем данные во временный буфер
			using (var ms = new MemoryStream(bufferSize))
			using (var writer = new BinaryWriter(ms))
			{
				// Заголовок
				writer.Write(header.Length);
				writer.Write(header);

				// Версия формата
				writer.Write((ushort)1);

				// User ID
				writer.Write((ushort)userId.Length);
				writer.Write(userId);

				// Credential ID
				writer.Write((ushort)credentialId.Length);
				writer.Write(credentialId);

				// Timestamp создания
				writer.Write(timestamp);

				// Вычисляем контрольную сумму от всех данных
				byte[] data = ms.ToArray();
				byte[] checksum;
				
				using (var sha256 = SHA256.Create())
				{
					checksum = sha256.ComputeHash(data);
				}

				// Теперь записываем всё в файл
				using (var fs = new FileStream(credentialFilePath, FileMode.Create, FileAccess.Write))
				using (var fileWriter = new BinaryWriter(fs))
				{
					fileWriter.Write(data);
					fileWriter.Write(checksum);
				}
			}
		}

		/// <summary>
		/// Загружает credential ID из файла
		/// </summary>
		/// <param name="databasePath">Путь к базе данных KeePass</param>
		/// <returns>Кортеж (credentialId, userId) или null, если файл не найден</returns>
		public static (byte[] credentialId, byte[] userId)? LoadCredentialId(string databasePath)
		{
			if (string.IsNullOrEmpty(databasePath))
			{
				throw new ArgumentException("Database path cannot be null or empty", nameof(databasePath));
			}

			string credentialFilePath = GetCredentialFilePath(databasePath);

			if (!File.Exists(credentialFilePath))
			{
				return null;
			}

			try
			{
				using (var fs = new FileStream(credentialFilePath, FileMode.Open, FileAccess.Read))
				using (var reader = new BinaryReader(fs))
				{
					// Читаем всё содержимое для проверки контрольной суммы
					long fileLength = fs.Length;
					byte[] allData = new byte[fileLength - 32]; // Без последних 32 байт (контрольная сумма)
					fs.Position = 0;
					fs.Read(allData, 0, allData.Length);

					// Читаем контрольную сумму
					byte[] storedChecksum = reader.ReadBytes(32);

					// Проверяем контрольную сумму
					using (var sha256 = SHA256.Create())
					{
						byte[] calculatedChecksum = sha256.ComputeHash(allData);
						
						for (int i = 0; i < 32; i++)
						{
							if (storedChecksum[i] != calculatedChecksum[i])
							{
								throw new InvalidDataException("Credential file checksum mismatch");
							}
						}
					}

					// Парсим данные
					fs.Position = 0;

					// Заголовок
					int headerLength = reader.ReadInt32();
					byte[] header = reader.ReadBytes(headerLength);
					string headerString = Encoding.UTF8.GetString(header);
					
					if (headerString != MAGIC_HEADER)
					{
						throw new InvalidDataException("Invalid credential file header");
					}

					// Версия
					ushort version = reader.ReadUInt16();
					if (version != 1)
					{
						throw new InvalidDataException($"Unsupported credential file version: {version}");
					}

					// User ID
					ushort userIdLength = reader.ReadUInt16();
					byte[] userId = reader.ReadBytes(userIdLength);

					// Credential ID
					ushort credentialIdLength = reader.ReadUInt16();
					byte[] credentialId = reader.ReadBytes(credentialIdLength);

					// Timestamp (читаем, но не используем пока)
					long timestamp = reader.ReadInt64();

					return (credentialId, userId);
				}
			}
			catch (Exception ex)
			{
				throw new InvalidDataException($"Failed to load credential ID: {ex.Message}", ex);
			}
		}

		/// <summary>
		/// Проверяет существование файла с credential ID
		/// </summary>
		public static bool CredentialExists(string databasePath)
		{
			if (string.IsNullOrEmpty(databasePath))
			{
				return false;
			}

			string credentialFilePath = GetCredentialFilePath(databasePath);
			return File.Exists(credentialFilePath);
		}

		/// <summary>
		/// Удаляет файл с credential ID
		/// </summary>
		public static void DeleteCredential(string databasePath)
		{
			if (string.IsNullOrEmpty(databasePath))
			{
				throw new ArgumentException("Database path cannot be null or empty", nameof(databasePath));
			}

			string credentialFilePath = GetCredentialFilePath(databasePath);
			
			if (File.Exists(credentialFilePath))
			{
				File.Delete(credentialFilePath);
			}
		}

		/// <summary>
		/// Получает путь к файлу с credential ID
		/// </summary>
		private static string GetCredentialFilePath(string databasePath)
		{
			// Заменяем расширение базы данных на .fido2
			string directory = Path.GetDirectoryName(databasePath);
			string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(databasePath);
			
			return Path.Combine(directory, fileNameWithoutExtension + FILE_EXTENSION);
		}
	}
}

