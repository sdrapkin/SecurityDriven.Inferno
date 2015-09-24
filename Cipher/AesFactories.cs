using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Cipher
{
	public static class AesFactories
	{
		internal static readonly Func<Aes> ManagedAes = () => new AesManaged();
		internal static readonly Func<Aes> FipsAes = () => new AesCryptoServiceProvider();

		public static readonly Func<Aes> Aes = Utils.AllowOnlyFipsAlgorithms ? FipsAes : ManagedAes;
	}//class AesFactories
}//ns