using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Kdf
{
	public class HKDF : DeriveBytes
	{
		HMAC hmac;
		int hashLength;
		byte[] context;
		static readonly byte[] emptyArray20 = new byte[20]; // for SHA-1
		static readonly byte[] emptyArray32 = new byte[32]; // for SHA-256
		static readonly byte[] emptyArray48 = new byte[48]; // for SHA-384
		static readonly byte[] emptyArray64 = new byte[64]; // for SHA-512
		byte counter;
		byte[] k;
		int k_unused;

		public HKDF(Func<HMAC> hmacFactory, byte[] ikm, byte[] salt = null, byte[] context = null)
		{
			hmac = hmacFactory();
			hashLength = hmac.OutputBlockSize;

			// a malicious implementation of HMAC could conceivably mess up the shared static empty byte arrays, which are still writeable...
			hmac.Key = salt ?? (hashLength == 64 ? emptyArray64 : hashLength == 48 ? emptyArray48 : hashLength == 32 ? emptyArray32 : hashLength == 20 ? emptyArray20 : new byte[hashLength]);
			hmac.Key = hmac.ComputeHash(ikm); // re-keying hmac with PRK
			this.context = context;
			Reset();
		}

		public override void Reset()
		{
			k = Utils.ZeroLengthArray<byte>.Value;
			k_unused = 0;
			counter = 0;
		}

		protected override void Dispose(bool disposing)
		{
			if (hmac != null)
				hmac.Dispose();
		}

		public override byte[] GetBytes(int countBytes)
		{
			var okm = new byte[countBytes];
			if (k_unused > 0)
			{
				var min = Math.Min(k_unused, countBytes);
				Utils.BlockCopy(k, hashLength - k_unused, okm, 0, min);
				countBytes -= min;
				k_unused -= min;
			}
			if (countBytes == 0) return okm;

			int n = countBytes / hashLength + 1;
			int contextLength = context != null ? context.Length : 0;
			byte[] hmac_msg = new byte[hashLength + contextLength + 1];

			for (var i = 1; i <= n; ++i)
			{
				Utils.BlockCopy(k, 0, hmac_msg, 0, k.Length);
				if (contextLength > 0)
					Utils.BlockCopy(context, 0, hmac_msg, k.Length, contextLength);

				hmac_msg[k.Length + contextLength] = checked(++counter);

				k = hmac.ComputeHash(hmac_msg, 0, k.Length + contextLength + 1);
				Utils.BlockCopy(k, 0, okm, okm.Length - countBytes, i < n ? hashLength : countBytes);
				countBytes -= hashLength;
			}
			k_unused = -countBytes;
			return okm;
		}// GetBytes()
	}// HKDF class
}//ns