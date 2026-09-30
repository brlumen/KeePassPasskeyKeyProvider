using System;
using System.IO;
using System.Security.Cryptography;
using KeePassLib.Collections;

namespace KeePassPasskeyKeyProvider.Tests
{
	internal static class TestData
	{
		public static byte[] Random(int length)
		{
			byte[] data = new byte[length];
			using (var rng = new RNGCryptoServiceProvider())
				rng.GetBytes(data);
			return data;
		}

		public static byte[] FromHex(string hex)
		{
			byte[] data = new byte[hex.Length / 2];
			for (int i = 0; i < data.Length; i++)
				data[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
			return data;
		}

		public static string ToHex(byte[] data)
		{
			return BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();
		}

		public static byte[] Serialize(KeyWrap wrap)
		{
			using (var ms = new MemoryStream())
			using (var bw = new BinaryWriter(ms))
			{
				wrap.Write(bw);
				bw.Flush();
				return ms.ToArray();
			}
		}

		public static KeyWrap Deserialize(byte[] data)
		{
			using (var br = new BinaryReader(new MemoryStream(data, false)))
				return KeyWrap.Read(br);
		}

		/// <summary>Minimal KDBX outer header: signatures, version, PublicCustomData (if any), end of header</summary>
		public static void WriteKdbxHeader(string path, VariantDictionary publicCustomData, uint version = 0x00040001)
		{
			using (var bw = new BinaryWriter(File.Create(path)))
			{
				bw.Write(0x9AA2D903u);
				bw.Write(0xB54BFB67u);
				bw.Write(version);
				if (publicCustomData != null)
				{
					byte[] data = VariantDictionary.Serialize(publicCustomData);
					bw.Write((byte)12);
					bw.Write(data.Length);
					bw.Write(data);
				}
				bw.Write((byte)0);
				bw.Write(4);
				bw.Write(new byte[] { 0x0D, 0x0A, 0x0D, 0x0A });
			}
		}
	}
}
