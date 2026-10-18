using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KeePassLib.Utility;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>P‑256 on macOS: Security.framework (SecKey), keys are never added to a keychain</summary>
	internal sealed class AppleP256 : IP256
	{
		private const string Library = "/System/Library/Frameworks/Security.framework/Security";
		private const int KeySize = 256;

		private static readonly IntPtr AttrKeyType = Constant("kSecAttrKeyType");
		private static readonly IntPtr AttrKeyTypeEC = Constant("kSecAttrKeyTypeECSECPrimeRandom");
		private static readonly IntPtr AttrKeySizeInBits = Constant("kSecAttrKeySizeInBits");
		private static readonly IntPtr AttrKeyClass = Constant("kSecAttrKeyClass");
		private static readonly IntPtr AttrKeyClassPrivate = Constant("kSecAttrKeyClassPrivate");
		private static readonly IntPtr AttrKeyClassPublic = Constant("kSecAttrKeyClassPublic");
		private static readonly IntPtr Ecdh = Constant("kSecKeyAlgorithmECDHKeyExchangeStandard");
		private static readonly IntPtr EcdsaSha256 = Constant("kSecKeyAlgorithmECDSASignatureMessageX962SHA256");

		public void GenerateKey(out byte[] privateKey, out byte[] publicKey)
		{
			using (CFHandle key = Generate())
			{
				byte[] blob = Export(key, true); // 0x04 ‖ X ‖ Y ‖ d
				try
				{
					if (blob.Length != P256.PublicKeyLength + P256.PrivateKeyLength)
						throw new CryptographicException("Unexpected private key format");
					publicKey = new byte[P256.PublicKeyLength];
					privateKey = new byte[P256.PrivateKeyLength];
					Array.Copy(blob, publicKey, publicKey.Length);
					Array.Copy(blob, publicKey.Length, privateKey, 0, privateKey.Length);
				}
				finally
				{
					MemUtil.ZeroByteArray(blob);
				}
			}
		}

		public byte[] DeriveKeyFromHash(byte[] privateKey, byte[] publicKey, byte[] peerPublicKey, byte[] label)
		{
			using (CFHandle key = ImportPrivateKey(privateKey, publicKey))
				return DeriveKeyFromHash(key, peerPublicKey, label);
		}

		public byte[] DeriveEphemeralKeyFromHash(byte[] peerPublicKey, byte[] label, out byte[] ephemeralPublicKey)
		{
			using (CFHandle ephemeral = Generate())
			{
				byte[] key = DeriveKeyFromHash(ephemeral, peerPublicKey, label);
				using (CFHandle ephemeralPublic = Check(SecKeyCopyPublicKey(ephemeral), IntPtr.Zero, "Public key export"))
					ephemeralPublicKey = Export(ephemeralPublic, false);
				return key;
			}
		}

		public byte[] SignData(byte[] privateKey, byte[] publicKey, byte[] data)
		{
			using (CFHandle key = ImportPrivateKey(privateKey, publicKey))
			using (CFHandle message = CoreFoundation.CreateData(data))
			using (CFHandle signature = Check(SecKeyCreateSignature(key, EcdsaSha256, message, out IntPtr error), error, "ECDSA signing"))
				return EcdsaSignature.FromDer(CoreFoundation.ReadData(signature));
		}

		public bool VerifyData(byte[] publicKey, byte[] data, byte[] signature)
		{
			using (CFHandle key = ImportPublicKey(publicKey))
			{
				if (signature == null || signature.Length != P256.SignatureLength)
					return false;
				using (CFHandle message = CoreFoundation.CreateData(data))
				using (CFHandle der = CoreFoundation.CreateData(EcdsaSignature.ToDer(signature)))
				{
					bool valid = SecKeyVerifySignature(key, EcdsaSha256, message, der, out IntPtr error);
					CoreFoundation.ReleaseError(error);
					return valid;
				}
			}
		}

		private static byte[] DeriveKeyFromHash(CFHandle privateKey, byte[] peerPublicKey, byte[] label)
		{
			using (CFHandle peer = ImportPublicKey(peerPublicKey))
			using (CFHandle parameters = CoreFoundation.CreateDictionary(new IntPtr[0], new IntPtr[0]))
			using (CFHandle sharedSecret = Check(SecKeyCopyKeyExchangeResult(privateKey, Ecdh, peer, parameters, out IntPtr error), error, "ECDH"))
			{
				byte[] z = CoreFoundation.ReadData(sharedSecret, true);
				try
				{
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
		}

		private static CFHandle Generate()
		{
			using (CFHandle size = CoreFoundation.CreateNumber(KeySize))
			using (CFHandle parameters = CoreFoundation.CreateDictionary(
				new[] { AttrKeyType, AttrKeySizeInBits }, new[] { AttrKeyTypeEC, size.DangerousGetHandle() }))
				return Check(SecKeyCreateRandomKey(parameters, out IntPtr error), error, "Key generation");
		}

		private static CFHandle ImportPrivateKey(byte[] privateKey, byte[] publicKey)
		{
			P256.CheckPublicKey(publicKey);
			if (privateKey == null || privateKey.Length != P256.PrivateKeyLength)
				throw new ArgumentException($"Expected {P256.PrivateKeyLength} bytes of private key");

			byte[] blob = new byte[P256.PublicKeyLength + P256.PrivateKeyLength];
			try
			{
				Array.Copy(publicKey, blob, publicKey.Length);
				Array.Copy(privateKey, 0, blob, publicKey.Length, privateKey.Length);
				return CreateKey(blob, AttrKeyClassPrivate);
			}
			finally
			{
				MemUtil.ZeroByteArray(blob);
			}
		}

		private static CFHandle ImportPublicKey(byte[] publicKey)
		{
			P256.CheckPublicKey(publicKey);
			return CreateKey(publicKey, AttrKeyClassPublic);
		}

		private static CFHandle CreateKey(byte[] blob, IntPtr keyClass)
		{
			using (CFHandle data = CoreFoundation.CreateData(blob))
			using (CFHandle attributes = CoreFoundation.CreateDictionary(
				new[] { AttrKeyType, AttrKeyClass }, new[] { AttrKeyTypeEC, keyClass }))
			{
				try
				{
					return Check(SecKeyCreateWithData(data, attributes, out IntPtr error), error, "Key import");
				}
				finally
				{
					CoreFoundation.WipeData(data);
				}
			}
		}

		private static byte[] Export(CFHandle key, bool secret)
		{
			using (CFHandle data = Check(SecKeyCopyExternalRepresentation(key, out IntPtr error), error, "Key export"))
				return CoreFoundation.ReadData(data, secret);
		}

		private static CFHandle Check(CFHandle result, IntPtr error, string operation)
		{
			if (!result.IsInvalid)
				return result;
			throw CoreFoundation.ToException(error, operation);
		}

		private static IntPtr Constant(string name)
		{
			return CoreFoundation.ReadConstant(Library, name);
		}

		[DllImport(Library)]
		private static extern CFHandle SecKeyCreateRandomKey(CFHandle parameters, out IntPtr error);

		[DllImport(Library)]
		private static extern CFHandle SecKeyCreateWithData(CFHandle keyData, CFHandle attributes, out IntPtr error);

		[DllImport(Library)]
		private static extern CFHandle SecKeyCopyExternalRepresentation(CFHandle key, out IntPtr error);

		[DllImport(Library)]
		private static extern CFHandle SecKeyCopyPublicKey(CFHandle key);

		[DllImport(Library)]
		private static extern CFHandle SecKeyCopyKeyExchangeResult(CFHandle privateKey, IntPtr algorithm, CFHandle publicKey,
			CFHandle parameters, out IntPtr error);

		[DllImport(Library)]
		private static extern CFHandle SecKeyCreateSignature(CFHandle key, IntPtr algorithm, CFHandle dataToSign, out IntPtr error);

		[DllImport(Library)]
		[return: MarshalAs(UnmanagedType.U1)]
		private static extern bool SecKeyVerifySignature(CFHandle key, IntPtr algorithm, CFHandle signedData, CFHandle signature,
			out IntPtr error);
	}
}
