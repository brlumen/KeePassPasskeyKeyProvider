using System;
using System.Runtime.InteropServices;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>OpenSSL 3 libcrypto functions for <see cref="OpenSslP256"/>, bound at run time (see <see cref="DynamicLibrary"/>)</summary>
	internal sealed class LibCrypto
	{
		// Linux; Homebrew on macOS (Apple silicon, Intel) for development
		private static readonly string[] Candidates =
		{
			"libcrypto.so.3",
			"/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
			"/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"
		};

		public readonly NewContextFromName EVP_PKEY_CTX_new_from_name;
		public readonly NewContextFromKey EVP_PKEY_CTX_new_from_pkey;
		public readonly Free EVP_PKEY_CTX_free;
		public readonly Free EVP_PKEY_free;
		public readonly Init EVP_PKEY_keygen_init;
		public readonly SetName EVP_PKEY_CTX_set_group_name;
		public readonly Generate EVP_PKEY_generate;
		public readonly Init EVP_PKEY_fromdata_init;
		public readonly FromData EVP_PKEY_fromdata;
		public readonly GetParams EVP_PKEY_get_params;
		public readonly Init EVP_PKEY_derive_init;
		public readonly SetPeer EVP_PKEY_derive_set_peer;
		public readonly Derive EVP_PKEY_derive;
		public readonly Init EVP_PKEY_sign_init;
		public readonly Sign EVP_PKEY_sign;
		public readonly Init EVP_PKEY_verify_init;
		public readonly Verify EVP_PKEY_verify;
		public readonly GetError ERR_get_error;
		public readonly ClearError ERR_clear_error;

		/// <exception cref="PlatformNotSupportedException">OpenSSL 3 is not installed</exception>
		public LibCrypto()
		{
			var library = new DynamicLibrary("libcrypto", Candidates, "OpenSSL 3 (libcrypto.so.3) is required for elliptic curve cryptography");
			EVP_PKEY_CTX_new_from_name = library.Bind<NewContextFromName>(nameof(EVP_PKEY_CTX_new_from_name));
			EVP_PKEY_CTX_new_from_pkey = library.Bind<NewContextFromKey>(nameof(EVP_PKEY_CTX_new_from_pkey));
			EVP_PKEY_CTX_free = library.Bind<Free>(nameof(EVP_PKEY_CTX_free));
			EVP_PKEY_free = library.Bind<Free>(nameof(EVP_PKEY_free));
			EVP_PKEY_keygen_init = library.Bind<Init>(nameof(EVP_PKEY_keygen_init));
			EVP_PKEY_CTX_set_group_name = library.Bind<SetName>(nameof(EVP_PKEY_CTX_set_group_name));
			EVP_PKEY_generate = library.Bind<Generate>(nameof(EVP_PKEY_generate));
			EVP_PKEY_fromdata_init = library.Bind<Init>(nameof(EVP_PKEY_fromdata_init));
			EVP_PKEY_fromdata = library.Bind<FromData>(nameof(EVP_PKEY_fromdata));
			EVP_PKEY_get_params = library.Bind<GetParams>(nameof(EVP_PKEY_get_params));
			EVP_PKEY_derive_init = library.Bind<Init>(nameof(EVP_PKEY_derive_init));
			EVP_PKEY_derive_set_peer = library.Bind<SetPeer>(nameof(EVP_PKEY_derive_set_peer));
			EVP_PKEY_derive = library.Bind<Derive>(nameof(EVP_PKEY_derive));
			EVP_PKEY_sign_init = library.Bind<Init>(nameof(EVP_PKEY_sign_init));
			EVP_PKEY_sign = library.Bind<Sign>(nameof(EVP_PKEY_sign));
			EVP_PKEY_verify_init = library.Bind<Init>(nameof(EVP_PKEY_verify_init));
			EVP_PKEY_verify = library.Bind<Verify>(nameof(EVP_PKEY_verify));
			ERR_get_error = library.Bind<GetError>(nameof(ERR_get_error));
			ERR_clear_error = library.Bind<ClearError>(nameof(ERR_clear_error));
		}

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr NewContextFromName(IntPtr libraryContext, string name, IntPtr propertyQuery);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr NewContextFromKey(IntPtr libraryContext, IntPtr key, IntPtr propertyQuery);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void Free(IntPtr handle);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int Init(IntPtr context);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int SetName(IntPtr context, string name);

		/// <summary>*key must be null on input: OpenSSL then allocates the key</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int Generate(IntPtr context, ref IntPtr key);

		/// <summary>*key must be null on input: OpenSSL then allocates the key</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int FromData(IntPtr context, ref IntPtr key, int selection, [In] OsslParam[] parameters);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int GetParams(IntPtr key, [In, Out] OsslParam[] parameters);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int SetPeer(IntPtr context, IntPtr peer);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int Derive(IntPtr context, [Out] byte[] secret, ref UIntPtr secretLength);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int Sign(IntPtr context, [Out] byte[] signature, ref UIntPtr signatureLength, byte[] digest, UIntPtr digestLength);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int Verify(IntPtr context, byte[] signature, UIntPtr signatureLength, byte[] digest, UIntPtr digestLength);

		/// <summary>unsigned long: pointer-sized on Linux and macOS</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate UIntPtr GetError();

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void ClearError();
	}

	/// <summary>OSSL_PARAM: a named value passed to or returned by OpenSSL; an array ends with a null key</summary>
	[StructLayout(LayoutKind.Sequential)]
	internal struct OsslParam
	{
		public const uint UnsignedInteger = 2; // native byte order
		public const uint Utf8String = 4;
		public const uint OctetString = 5;

		public IntPtr Key;
		public uint DataType;
		public IntPtr Data;
		public UIntPtr DataSize;
		public UIntPtr ReturnSize;

		public OsslParam(IntPtr key, uint dataType, IntPtr data, int dataSize)
		{
			Key = key;
			DataType = dataType;
			Data = data;
			DataSize = (UIntPtr)dataSize;
			ReturnSize = UIntPtr.Zero;
		}
	}
}
