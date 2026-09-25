using System;
using System.Collections.Generic;
using System.IO;
using KeePass;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
using KeePassLib.Serialization;

namespace KeePassPasskeyKeyProvider
{
	public enum HelloCredentialStatus
	{
		/// <summary>Credential is present in an open database or in the header of an existing or recently used database</summary>
		InUse,
		/// <summary>
		/// No database at the stored path although its folder is reachable. The database may still exist elsewhere
		/// (moved, renamed, saved under another name), which is not detected.
		/// </summary>
		DatabaseMissing,
		/// <summary>Database exists but its header lacks the credential (device removed or master key changed)</summary>
		NotInDatabase,
		/// <summary>Database not found on a removable or network drive, or its folder is unreachable (URL): it may still exist</summary>
		LocationUnavailable,
		/// <summary>Path unknown (credential created before paths were stored); not found in open or recently used databases</summary>
		Unknown
	}

	public sealed class HelloCredentialInfo
	{
		public PlatformCredential Credential { get; set; }
		public string DatabasePath { get; set; }
		public HelloCredentialStatus Status { get; set; }

		public string StatusText
		{
			get
			{
				switch (Status)
				{
					case HelloCredentialStatus.InUse: return Strings.StatusInUse;
					case HelloCredentialStatus.DatabaseMissing: return Strings.StatusDatabaseMissing;
					case HelloCredentialStatus.NotInDatabase: return Strings.StatusNotInDatabase;
					case HelloCredentialStatus.LocationUnavailable: return Strings.StatusLocationUnavailable;
					default: return Strings.StatusPathUnknown;
				}
			}
		}
	}

	/// <summary>
	/// Matches the plugin's Windows Hello credentials to databases: the path comes from the credential's displayName,
	/// membership from the device records in the header (the database need not be opened). Open databases and
	/// KeePass's recently used files are checked too, since a database may have been moved or renamed.
	/// </summary>
	public static class HelloCredentialAudit
	{
		public static List<HelloCredentialInfo> Run(IPluginHost host)
		{
			var result = new List<HelloCredentialInfo>();
			var headerCache = new Dictionary<string, List<DeviceRecord>>(StringComparer.OrdinalIgnoreCase);
			List<DeviceRecord> recentRecords = null;

			foreach (PlatformCredential cred in WebAuthnHelper.ListPlatformCredentials())
			{
				string path = LooksLikePath(cred.DisplayName) ? cred.DisplayName : null;
				HelloCredentialStatus status;
				if (IsInOpenDatabase(host, cred.CredentialId))
					status = HelloCredentialStatus.InUse;
				else
				{
					status = Classify(cred.CredentialId, path, headerCache);
					if (status != HelloCredentialStatus.InUse)
					{
						if (recentRecords == null) recentRecords = LoadRecentFileRecords(headerCache);
						if (DeviceKeyStore.Find(recentRecords, cred.CredentialId) != null)
							status = HelloCredentialStatus.InUse;
					}
				}

				result.Add(new HelloCredentialInfo { Credential = cred, DatabasePath = path, Status = status });
			}
			return result;
		}

		private static HelloCredentialStatus Classify(byte[] credentialId, string path,
			Dictionary<string, List<DeviceRecord>> headerCache)
		{
			if (path == null)
				return HelloCredentialStatus.Unknown;

			if (!File.Exists(path))
			{
				return !IsOnRemovableOrNetworkDrive(path) && IsFolderReachable(path)
					? HelloCredentialStatus.DatabaseMissing
					: HelloCredentialStatus.LocationUnavailable;
			}

			return DeviceKeyStore.Find(LoadHeaderRecords(path, headerCache), credentialId) != null
				? HelloCredentialStatus.InUse
				: HelloCredentialStatus.NotInDatabase;
		}

		/// <summary>Device records of all existing local files in KeePass's recently used list</summary>
		private static List<DeviceRecord> LoadRecentFileRecords(Dictionary<string, List<DeviceRecord>> headerCache)
		{
			var records = new List<DeviceRecord>();
			List<IOConnectionInfo> recent = Program.Config?.Application?.MostRecentlyUsed?.Items;
			if (recent == null) return records;

			foreach (IOConnectionInfo ioc in recent)
			{
				// Remote URLs are skipped: reading them may be slow or ask for credentials
				if (ioc == null || !ioc.IsLocalFile() || string.IsNullOrEmpty(ioc.Path)) continue;
				try
				{
					if (File.Exists(ioc.Path))
						records.AddRange(LoadHeaderRecords(ioc.Path, headerCache));
				}
				catch { /* invalid path */ }
			}
			return records;
		}

		private static List<DeviceRecord> LoadHeaderRecords(string path, Dictionary<string, List<DeviceRecord>> headerCache)
		{
			List<DeviceRecord> records;
			if (!headerCache.TryGetValue(path, out records))
			{
				try { records = DeviceKeyStore.LoadFromFile(IOConnectionInfo.FromPath(path)); }
				catch { records = new List<DeviceRecord>(); }
				headerCache[path] = records;
			}
			return records;
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
				catch { /* corrupted records: treat as not found */ }
			}
			return false;
		}

		/// <summary>A missing file on such a drive may just be on a disconnected medium or an offline share</summary>
		private static bool IsOnRemovableOrNetworkDrive(string path)
		{
			try
			{
				if (path.StartsWith(@"\\", StringComparison.Ordinal)) return true; // UNC path
				string root = Path.GetPathRoot(path);
				if (string.IsNullOrEmpty(root)) return true;
				DriveType type = new DriveInfo(root).DriveType;
				return type == DriveType.Removable || type == DriveType.CDRom || type == DriveType.Network
					|| type == DriveType.NoRootDirectory;
			}
			catch { return true; } // URL or invalid path
		}

		private static bool IsFolderReachable(string path)
		{
			try { return Directory.Exists(Path.GetDirectoryName(path)); }
			catch { return false; } // URL or invalid path
		}

		private static bool LooksLikePath(string s)
		{
			return !string.IsNullOrEmpty(s) && (s.Contains("\\") || s.Contains("/")) && !s.StartsWith("KeePass: ");
		}
	}
}
