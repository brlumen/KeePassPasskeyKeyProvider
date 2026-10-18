using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KeePassPasskeyKeyProvider.Ecc
{
	/// <summary>Owned reference to a Core Foundation object (a Create or Copy result), released with CFRelease</summary>
	internal sealed class CFHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		private CFHandle() : base(true)
		{
		}

		protected override bool ReleaseHandle()
		{
			CoreFoundation.CFRelease(handle);
			return true;
		}
	}

	/// <summary>Core Foundation interop for <see cref="AppleP256"/></summary>
	internal static class CoreFoundation
	{
		private const string Library = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
		private const string LibSystem = "/usr/lib/libSystem.B.dylib";
		private const int RTLD_NOW = 2;
		private const long kCFNumberSInt32Type = 3;

		private static readonly IntPtr dictionaryKeyCallBacks = Symbol(Library, "kCFTypeDictionaryKeyCallBacks");
		private static readonly IntPtr dictionaryValueCallBacks = Symbol(Library, "kCFTypeDictionaryValueCallBacks");

		/// <summary>Value of a constant exported by a framework, such as a CFStringRef key</summary>
		public static IntPtr ReadConstant(string library, string name)
		{
			return Marshal.ReadIntPtr(Symbol(library, name));
		}

		public static CFHandle CreateData(byte[] data)
		{
			return CheckCreated(CFDataCreate(IntPtr.Zero, data, data.Length));
		}

		/// <summary>Copy of the bytes of a CFData, which is then zeroed if <paramref name="wipe"/> (see <see cref="WipeData"/>)</summary>
		public static byte[] ReadData(CFHandle data, bool wipe = false)
		{
			byte[] result = new byte[checked((int)CFDataGetLength(data))];
			Marshal.Copy(CFDataGetBytePtr(data), result, 0, result.Length);
			if (wipe)
				WipeData(data);
			return result;
		}

		/// <summary>Zeroes the bytes of a CFData holding a secret: only when no one else references it</summary>
		public static void WipeData(CFHandle data)
		{
			int length = checked((int)CFDataGetLength(data));
			Marshal.Copy(new byte[length], 0, CFDataGetBytePtr(data), length);
		}

		public static CFHandle CreateNumber(int value)
		{
			return CheckCreated(CFNumberCreate(IntPtr.Zero, kCFNumberSInt32Type, ref value));
		}

		/// <summary>Dictionary that retains its keys and values</summary>
		public static CFHandle CreateDictionary(IntPtr[] keys, IntPtr[] values)
		{
			return CheckCreated(CFDictionaryCreate(IntPtr.Zero, keys, values, keys.Length, dictionaryKeyCallBacks, dictionaryValueCallBacks));
		}

		/// <summary>Exception for the CFErrorRef of a failed call; releases the error</summary>
		public static CryptographicException ToException(IntPtr error, string operation)
		{
			if (error == IntPtr.Zero)
				return new CryptographicException($"{operation} failed");
			long code = CFErrorGetCode(error);
			CFRelease(error);
			return new CryptographicException($"{operation} failed (error {code})");
		}

		public static void ReleaseError(IntPtr error)
		{
			if (error != IntPtr.Zero)
				CFRelease(error);
		}

		private static CFHandle CheckCreated(CFHandle handle)
		{
			if (handle.IsInvalid)
				throw new OutOfMemoryException();
			return handle;
		}

		private static IntPtr Symbol(string library, string name)
		{
			IntPtr handle = dlopen(library, RTLD_NOW);
			IntPtr symbol = handle == IntPtr.Zero ? IntPtr.Zero : dlsym(handle, name);
			if (symbol == IntPtr.Zero)
				throw new PlatformNotSupportedException($"{name} is missing in {library}");
			return symbol;
		}

		[DllImport(Library)]
		internal static extern void CFRelease(IntPtr cf);

		[DllImport(Library)]
		private static extern CFHandle CFDataCreate(IntPtr allocator, byte[] bytes, long length);

		[DllImport(Library)]
		private static extern long CFDataGetLength(CFHandle data);

		[DllImport(Library)]
		private static extern IntPtr CFDataGetBytePtr(CFHandle data);

		[DllImport(Library)]
		private static extern CFHandle CFNumberCreate(IntPtr allocator, long type, ref int value);

		[DllImport(Library)]
		private static extern CFHandle CFDictionaryCreate(IntPtr allocator, IntPtr[] keys, IntPtr[] values, long count,
			IntPtr keyCallBacks, IntPtr valueCallBacks);

		[DllImport(Library)]
		private static extern long CFErrorGetCode(IntPtr error);

		[DllImport(LibSystem)]
		private static extern IntPtr dlopen(string path, int mode);

		[DllImport(LibSystem)]
		private static extern IntPtr dlsym(IntPtr handle, string symbol);
	}
}
