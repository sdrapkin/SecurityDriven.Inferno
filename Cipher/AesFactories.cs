using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Cipher
{
	public static class AesFactories
	{
		internal static readonly Func<Aes> ManagedAes = () => new AesManaged();
		internal static readonly Func<Aes> FipsAes = Environment.OSVersion.Platform == PlatformID.Win32NT ?
			(Func<Aes>)(() => new AesCng()) :		// Windows
			() => new AesCryptoServiceProvider();	// non-Windows

		public static readonly Func<Aes> Aes = Utils.AllowOnlyFipsAlgorithms ? FipsAes : ManagedAes;
	}//class AesFactories
}//ns