using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Hash
{
	public static class HashFactories
	{
		static readonly Func<SHA1> ManagedSHA1 = () => new SHA1Managed();
		static readonly Func<SHA1> FipsSHA1 =
#if NET462
			() => new SHA1Cng();
#else
			() => System.Security.Cryptography.SHA1.Create();
#endif
		static readonly Func<SHA256> ManagedSHA256 = () => new SHA256Managed();
		static readonly Func<SHA256> FipsSHA256 =
#if NET462
			() => new SHA256Cng();
#else
			() => System.Security.Cryptography.SHA256.Create();
#endif
		static readonly Func<SHA384> ManagedSHA384 = () => new SHA384Managed();
		static readonly Func<SHA384> FipsSHA384 =
#if NET462
			() => new SHA384Cng();
#else
			() => System.Security.Cryptography.SHA384.Create();
#endif

		static readonly Func<SHA512> ManagedSHA512 = () => new SHA512Managed();
		static readonly Func<SHA512> FipsSHA512 =
#if NET462
			() => new SHA512Cng();
#else
			() => System.Security.Cryptography.SHA512.Create();
#endif

		internal static readonly Func<SHA1> SHA1 = Utils.AllowOnlyFipsAlgorithms ? FipsSHA1 : ManagedSHA1;
		public static readonly Func<SHA256> SHA256 = Utils.AllowOnlyFipsAlgorithms ? FipsSHA256 : ManagedSHA256;
		public static readonly Func<SHA384> SHA384 = Utils.AllowOnlyFipsAlgorithms ? FipsSHA384 : ManagedSHA384;
		public static readonly Func<SHA512> SHA512 = Utils.AllowOnlyFipsAlgorithms ? FipsSHA512 : ManagedSHA512;
	}// HashFactories class
}//ns