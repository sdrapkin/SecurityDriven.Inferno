using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno
{
	//https://www.nsa.gov/ia/programs/suiteb_cryptography/ - TOP SECRET MODE only
	public static class SuiteB
	{
		public static readonly Func<SHA384> HashFactory = Hash.HashFactories.SHA384;
		public static readonly Func<HMAC> HmacFactory = Mac.HMACFactories.HMACSHA384;

		public static byte[] Encrypt(byte[] masterKey, ArraySegment<byte> plaintext, ArraySegment<byte>? salt = null)
		{
			return EtM_CTR.Encrypt(masterKey, plaintext, salt);
		}

		public static byte[] Decrypt(byte[] masterKey, ArraySegment<byte> ciphertext, ArraySegment<byte>? salt = null)
		{
			return EtM_CTR.Decrypt(masterKey, ciphertext, salt);
		}

		public static bool Authenticate(byte[] masterKey, ArraySegment<byte> ciphertext, ArraySegment<byte>? salt = null)
		{
			return EtM_CTR.Authenticate(masterKey, ciphertext, salt);
		}
	}// class SuiteB
}//ns