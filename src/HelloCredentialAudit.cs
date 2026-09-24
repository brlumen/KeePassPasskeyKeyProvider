using System;
using System.Collections.Generic;
using System.IO;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskey.WebAuthn;
using KeePassLib;
using KeePassLib.Serialization;

namespace KeePassPasskey
{
	public enum HelloCredentialStatus
	{
		/// <summary>Credential есть в заголовке существующей базы</summary>
		InUse,
		/// <summary>Файл базы по сохранённому пути не найден — можно удалять</summary>
		DatabaseMissing,
		/// <summary>База есть, но credential в её заголовке нет (сменён мастер‑ключ или база старого формата)</summary>
		NotInDatabase,
		/// <summary>Путь неизвестен (credential создан до сохранения пути), в открытых базах не найден</summary>
		Unknown
	}

	public sealed class HelloCredentialInfo
	{
		public PlatformCredential Credential { get; set; }
		public string DatabasePath { get; set; }
		public HelloCredentialStatus Status { get; set; }

		public bool IsSafeToDelete => Status == HelloCredentialStatus.DatabaseMissing;

		public string StatusText
		{
			get
			{
				switch (Status)
				{
					case HelloCredentialStatus.InUse: return "используется";
					case HelloCredentialStatus.DatabaseMissing: return "база не найдена";
					case HelloCredentialStatus.NotInDatabase: return "в заголовке базы отсутствует";
					default: return "путь неизвестен";
				}
			}
		}
	}

	/// <summary>
	/// Сопоставляет credential Windows Hello плагина с базами: путь берётся из displayName credential,
	/// принадлежность — из записей устройств в заголовке (база открывать не нужно).
	/// </summary>
	public static class HelloCredentialAudit
	{
		public static List<HelloCredentialInfo> Run(IPluginHost host)
		{
			var result = new List<HelloCredentialInfo>();
			var headerCache = new Dictionary<string, List<DeviceRecord>>(StringComparer.OrdinalIgnoreCase);

			foreach (PlatformCredential cred in WebAuthnHelper.ListPlatformCredentials())
			{
				string path = LooksLikePath(cred.DisplayName) ? cred.DisplayName : null;
				result.Add(new HelloCredentialInfo
				{
					Credential = cred,
					DatabasePath = path,
					Status = Classify(host, cred.CredentialId, path, headerCache)
				});
			}
			return result;
		}

		private static HelloCredentialStatus Classify(IPluginHost host, byte[] credentialId, string path,
			Dictionary<string, List<DeviceRecord>> headerCache)
		{
			if (path == null)
			{
				return IsInOpenDatabase(host, credentialId)
					? HelloCredentialStatus.InUse
					: HelloCredentialStatus.Unknown;
			}

			if (!File.Exists(path))
				return HelloCredentialStatus.DatabaseMissing;

			List<DeviceRecord> records;
			if (!headerCache.TryGetValue(path, out records))
			{
				try { records = DeviceKeyStore.LoadFromFile(IOConnectionInfo.FromPath(path)); }
				catch { records = new List<DeviceRecord>(); }
				headerCache[path] = records;
			}

			return DeviceKeyStore.Find(records, credentialId) != null
				? HelloCredentialStatus.InUse
				: HelloCredentialStatus.NotInDatabase;
		}

		private static bool IsInOpenDatabase(IPluginHost host, byte[] credentialId)
		{
			foreach (PwDocument doc in host.MainWindow.DocumentManager.Documents)
			{
				PwDatabase db = doc.Database;
				if (db == null || !db.IsOpen) continue;
				try
				{
					if (DeviceKeyStore.Find(DeviceKeyStore.Load(db), credentialId) != null)
						return true;
				}
				catch { /* повреждённые записи — считаем, что не найден */ }
			}
			return false;
		}

		private static bool LooksLikePath(string s)
		{
			return !string.IsNullOrEmpty(s) && (s.Contains("\\") || s.Contains("/")) && !s.StartsWith("KeePass: ");
		}
	}
}
