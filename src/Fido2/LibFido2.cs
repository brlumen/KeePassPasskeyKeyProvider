using System;
using System.Runtime.InteropServices;

namespace KeePassPasskeyKeyProvider.Fido2
{
	/// <summary>
	/// libfido2 functions for <see cref="Fido2Authenticator"/> (fido.h of libfido2 1.x), bound at run time
	/// (see <see cref="DynamicLibrary"/>). Strings returned by libfido2 are pointers it owns, never marshalled strings.
	/// </summary>
	internal sealed class LibFido2
	{
		// Linux (package libfido2-1); Homebrew on macOS (Apple silicon, Intel) for development
		private static readonly string[] Candidates =
		{
			"libfido2.so.1",
			"/opt/homebrew/opt/libfido2/lib/libfido2.1.dylib",
			"/usr/local/opt/libfido2/lib/libfido2.1.dylib"
		};

		// fido/err.h
		public const int FIDO_OK = 0x00;
		public const int FIDO_ERR_UNSUPPORTED_EXTENSION = 0x16;
		public const int FIDO_ERR_OPERATION_DENIED = 0x27;
		public const int FIDO_ERR_UNSUPPORTED_OPTION = 0x2b;
		public const int FIDO_ERR_INVALID_OPTION = 0x2c;
		public const int FIDO_ERR_KEEPALIVE_CANCEL = 0x2d;
		public const int FIDO_ERR_NO_CREDENTIALS = 0x2e;
		public const int FIDO_ERR_USER_ACTION_TIMEOUT = 0x2f;
		public const int FIDO_ERR_PIN_INVALID = 0x31;
		public const int FIDO_ERR_PIN_BLOCKED = 0x32;
		public const int FIDO_ERR_PIN_AUTH_BLOCKED = 0x34;
		public const int FIDO_ERR_PIN_NOT_SET = 0x35;
		public const int FIDO_ERR_PIN_REQUIRED = 0x36;
		public const int FIDO_ERR_PIN_POLICY_VIOLATION = 0x37;
		public const int FIDO_ERR_ACTION_TIMEOUT = 0x3a;
		public const int FIDO_ERR_UV_BLOCKED = 0x3c;
		public const int FIDO_ERR_UV_INVALID = 0x3f;

		// fido/param.h, fido/types.h (fido_opt_t)
		public const int FIDO_EXT_HMAC_SECRET = 0x01;
		public const int FIDO_OPT_FALSE = 1;
		public const int FIDO_OPT_TRUE = 2;

		public readonly Init fido_init;
		public readonly Strerr fido_strerr;
		public readonly DevInfoNew fido_dev_info_new;
		public readonly DevInfoFree fido_dev_info_free;
		public readonly DevInfoManifest fido_dev_info_manifest;
		public readonly DevInfoPtr fido_dev_info_ptr;
		public readonly DevInfoString fido_dev_info_path;
		public readonly DevInfoString fido_dev_info_manufacturer_string;
		public readonly DevInfoString fido_dev_info_product_string;
		public readonly New fido_dev_new;
		public readonly Free fido_dev_free;
		public readonly DevOpen fido_dev_open;
		public readonly DevCommand fido_dev_close;
		public readonly DevCommand fido_dev_cancel;
		public readonly DevFlag fido_dev_is_fido2;
		public readonly DevFlag fido_dev_has_pin;
		public readonly DevFlag fido_dev_has_uv;
		public readonly DevRetryCount fido_dev_get_retry_count;
		public readonly New fido_cbor_info_new;
		public readonly Free fido_cbor_info_free;
		public readonly DevGetCborInfo fido_dev_get_cbor_info;
		public readonly Pointer fido_cbor_info_extensions_ptr;
		public readonly Length fido_cbor_info_extensions_len;
		public readonly Limit fido_cbor_info_maxcredidlen;
		public readonly Limit fido_cbor_info_maxcredcntlst;
		public readonly New fido_assert_new;
		public readonly Free fido_assert_free;
		public readonly SetString fido_assert_set_rp;
		public readonly SetBytes fido_assert_set_clientdata_hash;
		public readonly SetBytes fido_assert_allow_cred;
		public readonly SetInt fido_assert_set_extensions;
		public readonly SetBytes fido_assert_set_hmac_salt;
		public readonly SetInt fido_assert_set_up;
		public readonly SetInt fido_assert_set_uv;
		public readonly DevGetAssert fido_dev_get_assert;
		public readonly StatementPointer fido_assert_id_ptr;
		public readonly StatementLength fido_assert_id_len;
		public readonly StatementPointer fido_assert_hmac_secret_ptr;
		public readonly StatementLength fido_assert_hmac_secret_len;

		/// <exception cref="PlatformNotSupportedException">libfido2 is not installed</exception>
		public LibFido2()
		{
			var library = new DynamicLibrary("libfido2", Candidates, "libfido2 (libfido2.so.1) is required for FIDO2 security keys");
			fido_init = library.Bind<Init>(nameof(fido_init));
			fido_strerr = library.Bind<Strerr>(nameof(fido_strerr));
			fido_dev_info_new = library.Bind<DevInfoNew>(nameof(fido_dev_info_new));
			fido_dev_info_free = library.Bind<DevInfoFree>(nameof(fido_dev_info_free));
			fido_dev_info_manifest = library.Bind<DevInfoManifest>(nameof(fido_dev_info_manifest));
			fido_dev_info_ptr = library.Bind<DevInfoPtr>(nameof(fido_dev_info_ptr));
			fido_dev_info_path = library.Bind<DevInfoString>(nameof(fido_dev_info_path));
			fido_dev_info_manufacturer_string = library.Bind<DevInfoString>(nameof(fido_dev_info_manufacturer_string));
			fido_dev_info_product_string = library.Bind<DevInfoString>(nameof(fido_dev_info_product_string));
			fido_dev_new = library.Bind<New>(nameof(fido_dev_new));
			fido_dev_free = library.Bind<Free>(nameof(fido_dev_free));
			fido_dev_open = library.Bind<DevOpen>(nameof(fido_dev_open));
			fido_dev_close = library.Bind<DevCommand>(nameof(fido_dev_close));
			fido_dev_cancel = library.Bind<DevCommand>(nameof(fido_dev_cancel));
			fido_dev_is_fido2 = library.Bind<DevFlag>(nameof(fido_dev_is_fido2));
			fido_dev_has_pin = library.Bind<DevFlag>(nameof(fido_dev_has_pin));
			fido_dev_has_uv = library.Bind<DevFlag>(nameof(fido_dev_has_uv));
			fido_dev_get_retry_count = library.Bind<DevRetryCount>(nameof(fido_dev_get_retry_count));
			fido_cbor_info_new = library.Bind<New>(nameof(fido_cbor_info_new));
			fido_cbor_info_free = library.Bind<Free>(nameof(fido_cbor_info_free));
			fido_dev_get_cbor_info = library.Bind<DevGetCborInfo>(nameof(fido_dev_get_cbor_info));
			fido_cbor_info_extensions_ptr = library.Bind<Pointer>(nameof(fido_cbor_info_extensions_ptr));
			fido_cbor_info_extensions_len = library.Bind<Length>(nameof(fido_cbor_info_extensions_len));
			fido_cbor_info_maxcredidlen = library.Bind<Limit>(nameof(fido_cbor_info_maxcredidlen));
			fido_cbor_info_maxcredcntlst = library.Bind<Limit>(nameof(fido_cbor_info_maxcredcntlst));
			fido_assert_new = library.Bind<New>(nameof(fido_assert_new));
			fido_assert_free = library.Bind<Free>(nameof(fido_assert_free));
			fido_assert_set_rp = library.Bind<SetString>(nameof(fido_assert_set_rp));
			fido_assert_set_clientdata_hash = library.Bind<SetBytes>(nameof(fido_assert_set_clientdata_hash));
			fido_assert_allow_cred = library.Bind<SetBytes>(nameof(fido_assert_allow_cred));
			fido_assert_set_extensions = library.Bind<SetInt>(nameof(fido_assert_set_extensions));
			fido_assert_set_hmac_salt = library.Bind<SetBytes>(nameof(fido_assert_set_hmac_salt));
			fido_assert_set_up = library.Bind<SetInt>(nameof(fido_assert_set_up));
			fido_assert_set_uv = library.Bind<SetInt>(nameof(fido_assert_set_uv));
			fido_dev_get_assert = library.Bind<DevGetAssert>(nameof(fido_dev_get_assert));
			fido_assert_id_ptr = library.Bind<StatementPointer>(nameof(fido_assert_id_ptr));
			fido_assert_id_len = library.Bind<StatementLength>(nameof(fido_assert_id_len));
			fido_assert_hmac_secret_ptr = library.Bind<StatementPointer>(nameof(fido_assert_hmac_secret_ptr));
			fido_assert_hmac_secret_len = library.Bind<StatementLength>(nameof(fido_assert_hmac_secret_len));
			fido_init(0);
		}

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void Init(int flags);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr Strerr(int code);

		/// <summary>Object constructor: fido_dev_new, fido_assert_new, fido_cbor_info_new</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr New();

		/// <summary>Object destructor: takes the address of the pointer and sets it to null</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void Free(ref IntPtr handle);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr DevInfoNew(UIntPtr count);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void DevInfoFree(ref IntPtr list, UIntPtr count);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int DevInfoManifest(IntPtr list, UIntPtr capacity, out UIntPtr found);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr DevInfoPtr(IntPtr list, UIntPtr index);

		/// <summary>const char * owned by the device list</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr DevInfoString(IntPtr info);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int DevOpen(IntPtr device, [MarshalAs(UnmanagedType.LPStr)] string path);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int DevCommand(IntPtr device);

		/// <summary>C bool: one byte</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		[return: MarshalAs(UnmanagedType.I1)]
		public delegate bool DevFlag(IntPtr device);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int DevRetryCount(IntPtr device, out int retries);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int DevGetCborInfo(IntPtr device, IntPtr info);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr Pointer(IntPtr handle);

		/// <summary>size_t of an object: fido_cbor_info_*_len</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate UIntPtr Length(IntPtr handle);

		/// <summary>uint64_t limit from authenticatorGetInfo; 0 if the authenticator does not report it</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate ulong Limit(IntPtr info);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int SetString(IntPtr assert, [MarshalAs(UnmanagedType.LPStr)] string value);

		/// <summary>libfido2 copies the bytes</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int SetBytes(IntPtr assert, byte[] data, UIntPtr length);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int SetInt(IntPtr assert, int value);

		/// <summary>pin: NUL-terminated UTF-8 or null; blocks until the authenticator answers</summary>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate int DevGetAssert(IntPtr device, IntPtr assert, byte[] pin);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr StatementPointer(IntPtr assert, UIntPtr index);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate UIntPtr StatementLength(IntPtr assert, UIntPtr index);
	}
}
