using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Mac
{
	public static class HMACFactories
	{
		public static readonly Func<HMAC2> HMACSHA1 = () => new HMAC2(Hash.HashFactories.SHA1);
		public static readonly Func<HMAC2> HMACSHA256 = () => new HMAC2(Hash.HashFactories.SHA256);
		public static readonly Func<HMAC2> HMACSHA384 = () => new HMAC2(Hash.HashFactories.SHA384);
		public static readonly Func<HMAC2> HMACSHA512 = () => new HMAC2(Hash.HashFactories.SHA512);
	}// HMACFactories class
}