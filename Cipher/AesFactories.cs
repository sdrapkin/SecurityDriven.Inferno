using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Cipher
{
	public static class AesFactories
	{
		internal static readonly Func<Aes> ManagedAes = () => new AesManaged();
		internal static readonly Func<Aes> FipsAes = Environment.OSVersion.Platform == PlatformID.Win32NT ?
#pragma warning disable CA1416 // Validate platform compatibility
            (Func<Aes>)(() => new AesCng()) :       // Windows
#pragma warning restore CA1416 // Validate platform compatibility
            () => new AesCryptoServiceProvider();	// non-Windows

		public static readonly Func<Aes> Aes = Utils.AllowOnlyFipsAlgorithms ? FipsAes : ManagedAes;
	}//class AesFactories
}//ns