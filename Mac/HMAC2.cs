using System;
using System.Reflection;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Mac
{
	using Extensions;

	public class HMAC2 : HMAC
	{
		HashAlgorithm h1, h2;
		public HMAC2(Func<HashAlgorithm> hashFactory)
		{
			h1 = hashFactory();
			h2 = hashFactory();

			m_hash1(this, h1);
			m_hash2(this, h2);

			this.HashSizeValue = h1.HashSize;
			if (h1 is SHA384Cng || h1 is SHA512Cng || h1 is SHA384 || h1 is SHA512)
				this.BlockSizeValue = 128; // parent HMAC class defaults to 64 bits
		}

		public HMAC2(Func<HashAlgorithm> hashFactory, byte[] key) : this(hashFactory) { this.Key = key; }
		public override int InputBlockSize => this.BlockSizeValue;
		public override int OutputBlockSize => this.HashSize >> 3;

		public new void HashCore(byte[] rgb, int ib, int cb) => base.HashCore(rgb, ib, cb);
		public new byte[] HashFinal() => base.HashFinal();

		/// <summary>
		/// Gets or sets the key to use in the hash algorithm.
		/// </summary>
		public override byte[] Key
		{
			get
			{
				return base.KeyValue.CloneBytes();
			}
			set
			{
				if (value.Length <= this.BlockSizeValue) h1.Initialize();
				h2.Initialize();
				base.Key = value;
			}
		}

		static readonly Action<HMAC2, HashAlgorithm> m_hash1;
		static readonly Action<HMAC2, HashAlgorithm> m_hash2;

		static HMAC2()
		{
			Type thisType = typeof(HMAC2);
			m_hash1 = thisType.GetField("m_hash1", BindingFlags.NonPublic | BindingFlags.Instance).CreateSetter<HMAC2, HashAlgorithm>();
			m_hash2 = thisType.GetField("m_hash2", BindingFlags.NonPublic | BindingFlags.Instance).CreateSetter<HMAC2, HashAlgorithm>();
		}//static ctor
	}// HMAC2 class
}//ns