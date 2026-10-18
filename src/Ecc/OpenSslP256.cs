using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>
	/// P‑256 outside Windows: OpenSSL 3 (libcrypto) through the EVP_PKEY interface. Keys are imported with
	/// EVP_PKEY_fromdata, which rejects a public point that is not on the curve. Signatures are made over
	/// a SHA‑256 digest computed here.
	/// </summary>
	internal sealed class OpenSslP256 : IP256
	{
		private const string Algorithm = "EC";
		private const string Curve = "P-256";
		private const int PublicKeySelection = 0x86; // EVP_PKEY_PUBLIC_KEY
		private const int KeyPairSelection = 0x87; // EVP_PKEY_KEYPAIR
		private const int MaxDerSignatureLength = 2 + 2 * (2 + 1 + P256.PrivateKeyLength); // SEQUENCE of two INTEGERs

		// OSSL_PARAM names and the curve name as C strings, allocated once for the process lifetime
		private static readonly IntPtr GroupParam = Marshal.StringToHGlobalAnsi("group");
		private static readonly IntPtr PublicKeyParam = Marshal.StringToHGlobalAnsi("pub");
		private static readonly IntPtr PrivateKeyParam = Marshal.StringToHGlobalAnsi("priv");
		private static readonly IntPtr CurveName = Marshal.StringToHGlobalAnsi(Curve);

		// Throws PlatformNotSupportedException if OpenSSL 3 is not installed
		private readonly LibCrypto lib = new LibCrypto();

		public void GenerateKey(out byte[] privateKey, out byte[] publicKey)
		{
			using (Handle key = Generate())
			{
				publicKey = ExportPublicKey(key);
				privateKey = GetParam(key, PrivateKeyParam, OsslParam.UnsignedInteger, P256.PrivateKeyLength);
				SwapNativeOrder(privateKey);
			}
		}

		public byte[] DeriveKeyFromHash(byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] label)
		{
			using (Handle key = Import(publicKey, privateKey))
				return DeriveKeyFromHash(key, peerPublicKey, label);
		}

		public byte[] DeriveEphemeralKeyFromHash(byte[] peerPublicKey, byte[] label, out byte[] ephemeralPublicKey)
		{
			using (Handle ephemeral = Generate())
			{
				ephemeralPublicKey = ExportPublicKey(ephemeral);
				return DeriveKeyFromHash(ephemeral, peerPublicKey, label);
			}
		}

		public byte[] SignData(byte[] privateKey, byte[] publicKey, byte[] data)
		{
			byte[] digest = Hash(data);
			using (Handle key = Import(publicKey, privateKey))
			using (Handle context = KeyContext(key, lib.EVP_PKEY_sign_init, "ECDSA signing"))
			{
				byte[] der = new byte[MaxDerSignatureLength];
				var length = (UIntPtr)der.Length;
				Check(lib.EVP_PKEY_sign(context.Value, der, ref length, digest, (UIntPtr)digest.Length), "ECDSA signing");
				Array.Resize(ref der, (int)(uint)length);
				return EcdsaSignature.FromDer(der);
			}
		}

		public bool VerifyData(byte[] publicKey, byte[] data, byte[] signature)
		{
			using (Handle key = Import(publicKey, null))
			{
				if (signature == null || signature.Length != P256.SignatureLength)
					return false;
				byte[] der = EcdsaSignature.ToDer(signature);
				byte[] digest = Hash(data);
				using (Handle context = KeyContext(key, lib.EVP_PKEY_verify_init, "ECDSA verification"))
				{
					// 1: valid; 0 or a negative error (such as r or s out of range): not valid
					bool valid = lib.EVP_PKEY_verify(context.Value, der, (UIntPtr)der.Length, digest, (UIntPtr)digest.Length) == 1;
					lib.ERR_clear_error();
					return valid;
				}
			}
		}

		private byte[] DeriveKeyFromHash(Handle key, byte[] peerPublicKey, byte[] label)
		{
			byte[] z = new byte[P256.PrivateKeyLength];
			try
			{
				using (Handle peer = Import(peerPublicKey, null))
				using (Handle context = KeyContext(key, lib.EVP_PKEY_derive_init, "ECDH"))
				{
					var length = (UIntPtr)z.Length;
					Check(lib.EVP_PKEY_derive_set_peer(context.Value, peer.Value), "ECDH");
					Check(lib.EVP_PKEY_derive(context.Value, z, ref length), "ECDH");
					if ((uint)length != z.Length)
						throw new CryptographicException("Unexpected ECDH secret length");
				}
				using (SHA256 sha = SHA256.Create())
				{
					sha.TransformBlock(z, 0, z.Length, null, 0);
					sha.TransformFinalBlock(label, 0, label.Length);
					return sha.Hash;
				}
			}
			finally
			{
				MemUtil.ZeroByteArray(z);
			}
		}

		private Handle Generate()
		{
			using (Handle context = AlgorithmContext(lib.EVP_PKEY_keygen_init, "Key generation"))
			{
				Check(lib.EVP_PKEY_CTX_set_group_name(context.Value, Curve), "Key generation");
				IntPtr key = IntPtr.Zero;
				return Key(lib.EVP_PKEY_generate(context.Value, ref key), key, "Key generation");
			}
		}

		/// <summary>Public key, or key pair if <paramref name="privateKey"/> is given; d is not checked against Q</summary>
		/// <exception cref="CryptographicException">The public key is not a point on the curve</exception>
		private Handle Import(byte[] publicKey, byte[] privateKey)
		{
			P256.CheckPublicKey(publicKey);
			if (privateKey != null && privateKey.Length != P256.PrivateKeyLength)
				throw new ArgumentException($"Expected {P256.PrivateKeyLength} bytes of private key");

			byte[] scalar = privateKey == null ? null : (byte[])privateKey.Clone();
			GCHandle publicData = GCHandle.Alloc(publicKey, GCHandleType.Pinned);
			GCHandle privateData = default(GCHandle);
			try
			{
				var parameters = new OsslParam[4];
				parameters[0] = new OsslParam(GroupParam, OsslParam.Utf8String, CurveName, Curve.Length);
				parameters[1] = new OsslParam(PublicKeyParam, OsslParam.OctetString, publicData.AddrOfPinnedObject(), publicKey.Length);
				if (scalar != null)
				{
					SwapNativeOrder(scalar);
					privateData = GCHandle.Alloc(scalar, GCHandleType.Pinned);
					parameters[2] = new OsslParam(PrivateKeyParam, OsslParam.UnsignedInteger, privateData.AddrOfPinnedObject(), scalar.Length);
				}

				using (Handle context = AlgorithmContext(lib.EVP_PKEY_fromdata_init, "Key import"))
				{
					IntPtr key = IntPtr.Zero;
					int selection = scalar == null ? PublicKeySelection : KeyPairSelection;
					return Key(lib.EVP_PKEY_fromdata(context.Value, ref key, selection, parameters), key, "Key import");
				}
			}
			finally
			{
				publicData.Free();
				if (privateData.IsAllocated)
					privateData.Free();
				if (scalar != null)
					MemUtil.ZeroByteArray(scalar);
			}
		}

		private byte[] ExportPublicKey(Handle key)
		{
			byte[] publicKey = GetParam(key, PublicKeyParam, OsslParam.OctetString, P256.PublicKeyLength);
			P256.CheckPublicKey(publicKey);
			return publicKey;
		}

		/// <summary>Key parameter of a fixed length (OpenSSL pads the private scalar to the curve size)</summary>
		private byte[] GetParam(Handle key, IntPtr name, uint type, int length)
		{
			byte[] value = new byte[length];
			GCHandle data = GCHandle.Alloc(value, GCHandleType.Pinned);
			try
			{
				OsslParam[] parameters = { new OsslParam(name, type, data.AddrOfPinnedObject(), length), default(OsslParam) };
				if (lib.EVP_PKEY_get_params(key.Value, parameters) == 1 && (ulong)parameters[0].ReturnSize == (ulong)length)
					return value;
				MemUtil.ZeroByteArray(value);
				throw Error("Key export");
			}
			finally
			{
				data.Free();
			}
		}

		private Handle AlgorithmContext(LibCrypto.Init init, string operation)
		{
			return Context(lib.EVP_PKEY_CTX_new_from_name(IntPtr.Zero, Algorithm, IntPtr.Zero), init, operation);
		}

		private Handle KeyContext(Handle key, LibCrypto.Init init, string operation)
		{
			return Context(lib.EVP_PKEY_CTX_new_from_pkey(IntPtr.Zero, key.Value, IntPtr.Zero), init, operation);
		}

		/// <summary>Owned EVP_PKEY_CTX after its initialization for an operation</summary>
		private Handle Context(IntPtr context, LibCrypto.Init init, string operation)
		{
			var handle = new Handle(context, lib.EVP_PKEY_CTX_free);
			if (context != IntPtr.Zero && init(context) == 1)
				return handle;
			handle.Dispose();
			throw Error(operation);
		}

		/// <summary>Owned EVP_PKEY returned by a call with the given result</summary>
		private Handle Key(int result, IntPtr key, string operation)
		{
			var handle = new Handle(key, lib.EVP_PKEY_free);
			if (result == 1 && key != IntPtr.Zero)
				return handle;
			handle.Dispose();
			throw Error(operation);
		}

		private void Check(int result, string operation)
		{
			if (result != 1)
				throw Error(operation);
		}

		/// <summary>Exception for a failed call with the OpenSSL error code (no key material); clears the error queue</summary>
		private CryptographicException Error(string operation)
		{
			ulong code = (ulong)lib.ERR_get_error();
			lib.ERR_clear_error();
			return new CryptographicException(code == 0 ? $"{operation} failed" : $"{operation} failed (OpenSSL error 0x{code:X})");
		}

		private static byte[] Hash(byte[] data)
		{
			using (SHA256 sha = SHA256.Create())
				return sha.ComputeHash(data);
		}

		/// <summary>Big-endian scalar ↔ OSSL_PARAM unsigned integer, which is in native byte order</summary>
		private static void SwapNativeOrder(byte[] value)
		{
			if (BitConverter.IsLittleEndian)
				Array.Reverse(value);
		}

		/// <summary>Native object freed on dispose (the free functions accept null)</summary>
		private sealed class Handle : IDisposable
		{
			private readonly LibCrypto.Free free;

			public Handle(IntPtr value, LibCrypto.Free free)
			{
				Value = value;
				this.free = free;
			}

			public IntPtr Value { get; }

			public void Dispose()
			{
				free(Value);
			}
		}
	}
}
