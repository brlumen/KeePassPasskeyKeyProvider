using System;
using System.Runtime.InteropServices;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Native library outside Windows, opened with dlopen and bound with dlsym: distributions ship only the versioned
	/// library (the unversioned name comes with the development package), and its name differs by OS, which a DllImport
	/// name cannot express. The library stays loaded for the process lifetime.
	/// </summary>
	internal sealed class DynamicLibrary
	{
		private const int RTLD_NOW = 2;

		// dlopen and dlsym: libdl.so.2 exists with every glibc (since 2.34 a stub over libc.so.6);
		// elsewhere they are in the C library, which Mono maps from "libc"
		private static readonly bool linux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

		private readonly string name;
		private readonly IntPtr handle;

		/// <summary>Opens the first of the candidate files that loads</summary>
		/// <param name="name">Library name for error messages</param>
		/// <param name="candidates">File names or paths, in order of preference</param>
		/// <param name="missingMessage">Message of the exception if none of them loads</param>
		/// <exception cref="PlatformNotSupportedException">None of the candidates loads</exception>
		public DynamicLibrary(string name, string[] candidates, string missingMessage)
		{
			this.name = name;
			try
			{
				foreach (string candidate in candidates)
				{
					handle = linux ? LinuxOpen(candidate, RTLD_NOW) : LibcOpen(candidate, RTLD_NOW);
					if (handle != IntPtr.Zero)
						return;
				}
			}
			catch (DllNotFoundException)
			{
				// No dlopen: Windows or a C library other than glibc
			}
			throw new PlatformNotSupportedException(missingMessage);
		}

		/// <exception cref="PlatformNotSupportedException">The library has no such function</exception>
		public T Bind<T>(string function) where T : Delegate
		{
			IntPtr pointer = linux ? LinuxSymbol(handle, function) : LibcSymbol(handle, function);
			if (pointer == IntPtr.Zero)
				throw new PlatformNotSupportedException($"{function} is missing in {name}");
			return Marshal.GetDelegateForFunctionPointer<T>(pointer);
		}

		[DllImport("libdl.so.2", EntryPoint = "dlopen")]
		private static extern IntPtr LinuxOpen(string fileName, int flags);

		[DllImport("libdl.so.2", EntryPoint = "dlsym")]
		private static extern IntPtr LinuxSymbol(IntPtr handle, string symbol);

		[DllImport("libc", EntryPoint = "dlopen")]
		private static extern IntPtr LibcOpen(string fileName, int flags);

		[DllImport("libc", EntryPoint = "dlsym")]
		private static extern IntPtr LibcSymbol(IntPtr handle, string symbol);
	}
}
