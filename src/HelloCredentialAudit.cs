using System;
using System.Collections.Generic;
using System.IO;
using KeePass.Plugins;
using KeePass.UI;
using KeePassPasskeyKeyProvider.WebAuthn;
using KeePassLib;
using KeePassLib.Serialization;

namespace KeePassPasskeyKeyProvider
{
	public enum HelloCredentialStatus
	{
		/// <summary>Credential is present in the header of an existing database or in an open database</summary>
		InUse,
		/// <summary>Database file not found at the stored path although its folder is reachable; safe to delete</summary>
		DatabaseMissing,
		/// <summary>Database exists but its header lacks the credential (master key changed or old-format database)</summary>
		NotInDatabase,
		/// <summary>Database folder is unreachable (removed drive, offline network share, URL): the database may still exist</summary>
		LocationUnavailable,
		/// <summary>Path unknown (credential created before paths were stored); not found in open databases</summary>
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
	/// membership from the device records in the header (the database need not be opened).
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
			// An open database may have been renamed or moved since the credential was created
			if (IsInOpenDatabase(host, credentialId))
				return HelloCredentialStatus.InUse;
			if (path == null)
				return HelloCredentialStatus.Unknown;

			if (!File.Exists(path))
			{
				return IsFolderReachable(path)
					? HelloCredentialStatus.DatabaseMissing
					: HelloCredentialStatus.LocationUnavailable;
			}

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
				catch { /* corrupted records: treat as not found */ }
			}
			return false;
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
