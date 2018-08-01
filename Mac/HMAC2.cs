using System;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Mac
{
	using Extensions;

	public class HMAC2 : HMAC
	{
		HashAlgorithm hashAlgorithm;

		int keyLength;
		int blockSizeValue = 128; // abstract HMAC class defaults to 64-byte block size, but we'll default to 128-byte
		bool isRekeying;
		bool isHashing;
		bool isHashDirty;

		const int MAX_HASH_BLOCK_SIZE = 1344 >> 3; // 1344 is max SHA-family block size in bits (https://en.wikipedia.org/wiki/SHA-3)
		static readonly long[] _ipadLongs = new Utils.Union { Bytes = Enumerable.Repeat<byte>(0x36, MAX_HASH_BLOCK_SIZE).ToArray() }.Longs;
		static readonly long[] _opadLongs = new Utils.Union { Bytes = Enumerable.Repeat<byte>(0x5c, MAX_HASH_BLOCK_SIZE).ToArray() }.Longs;

		static readonly Func<HashAlgorithm, byte[]> _HashValue_Getter =
			Utils.CreateGetter<HashAlgorithm, byte[]>(typeof(HashAlgorithm).GetField("HashValue", BindingFlags.Instance | BindingFlags.NonPublic));

		#region ctors
		public HMAC2(Func<HashAlgorithm> hashFactory)
		{
			hashAlgorithm = hashFactory();
			base.HashSizeValue = hashAlgorithm.HashSize;
#if NET462
			if (hashAlgorithm is SHA384Cng || hashAlgorithm is SHA512Cng || hashAlgorithm is SHA384 || hashAlgorithm is SHA512)
#elif NETCOREAPP2_1
			if (hashAlgorithm is SHA384 || hashAlgorithm is SHA512)
#endif
			{
				base.BlockSizeValue = blockSizeValue;
			}
			else blockSizeValue = 64;

			// [block-sized raw key value] || [ipad xor'ed into block-sized raw key value] || [opad xor'ed into block-sized raw key value]
			base.KeyValue = new byte[blockSizeValue * 3];
		}// ctor

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public HMAC2(Func<HashAlgorithm> hashFactory, byte[] key) : this(hashFactory) { this.Key = key; }
		#endregion

		#region overrides
		public override byte[] Key
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				var keyValueClone = new byte[keyLength];
				for (int i = 0; i < keyValueClone.Length; ++i) keyValueClone[i] = base.KeyValue[i];
				return keyValueClone;
			}
			set
			{
				if (isHashing) throw new CryptographicException("Hash key cannot be changed after the first write to the stream.");
				if (isHashDirty) { hashAlgorithm.Initialize(); isHashDirty = false; }

				var blockSizeValue = this.blockSizeValue;

				if (value.Length > blockSizeValue)
				{
					hashAlgorithm.TransformBlock(value, 0, value.Length, null, 0);
					hashAlgorithm.TransformFinalBlock(value, 0, 0);
					value = _HashValue_Getter(hashAlgorithm);

					hashAlgorithm.Initialize();
				}
				var keyLength = value.Length;
				this.keyLength = keyLength;

				var keyValue = base.KeyValue;

				Utils.BlockCopy(value, 0, keyValue, 0, keyLength);
				//for (int i = 0; i < keyLength; ++i) keyValue[i] = value[i];

				if (isRekeying) Array.Clear(keyValue, keyLength, blockSizeValue - keyLength);
				else isRekeying = true;

				//Utils.Xor(dest: keyValue, destOffset: blockSizeValue, left: ipad, leftOffset: 0, right: keyValue, rightOffset: 0, byteCount: blockSizeValue);
				//Utils.Xor(dest: keyValue, destOffset: blockSizeValue << 1, left: opad, leftOffset: 0, right: keyValue, rightOffset: 0, byteCount: blockSizeValue);

				long[] keyValueLongs = new Utils.Union { Bytes = keyValue }.Longs, ipadLongs = _ipadLongs, opadLongs = _opadLongs;
				blockSizeValue = blockSizeValue >> 3;

				for (int i = 0, blockSizeValue_x2 = blockSizeValue << 1; i < blockSizeValue; ++i)
				{
					keyValueLongs[blockSizeValue + i] = keyValueLongs[i] ^ ipadLongs[i];
					keyValueLongs[blockSizeValue_x2 + i] = keyValueLongs[i] ^ opadLongs[i];
				}
			}//setter
		}// Key

		public new string HashName
		{
			get
			{
				return hashAlgorithm.ToString();
			}
			set
			{
				throw new NotSupportedException("Do not set underlying hash algorithm via 'HashName' property - use constructor instead.");
			}
		}// HashName

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (hashAlgorithm != null)
				{
					hashAlgorithm.Dispose(); // will also clear base.HashValue
					hashAlgorithm = null;
				}

				if (base.KeyValue != null)
				{
					Array.Clear(this.KeyValue, 0, this.KeyValue.Length);
					this.KeyValue = null;
				}
			}
			// intentionally do not call base.Dispose(disposing)
		}// Dispose()

		public override byte[] Hash
		{
			get
			{
				if (hashAlgorithm == null) throw new ObjectDisposedException(nameof(hashAlgorithm));
				if (base.State != 0) throw new CryptographicUnexpectedOperationException("Hash must be finalized before the hash value is retrieved.");

				var hashValue = base.HashValue;
				var hashValueClone = new byte[hashValue.Length];
				for (int i = 0; i < hashValueClone.Length; ++i) hashValueClone[i] = hashValue[i];
				return hashValueClone;
			}
		}// Hash

		protected override void HashCore(byte[] rgb, int ib, int cb)
		{
			if (isHashDirty) { hashAlgorithm.Initialize(); isHashDirty = false; }
			if (isHashing == false)
			{
				hashAlgorithm.TransformBlock(base.KeyValue, blockSizeValue, blockSizeValue, null, 0);
				isHashing = true;
			}
			hashAlgorithm.TransformBlock(rgb, ib, cb, null, 0);
		}// HashCore()

		protected override byte[] HashFinal()
		{
			if (isHashDirty) { hashAlgorithm.Initialize(); } else isHashDirty = true;
			if (isHashing == false) hashAlgorithm.TransformBlock(base.KeyValue, blockSizeValue, blockSizeValue, null, 0);
			else isHashing = false;

			// finalize the original hash
			hashAlgorithm.TransformFinalBlock(base.KeyValue, 0, 0);
			byte[] innerHash = _HashValue_Getter(hashAlgorithm);

			hashAlgorithm.Initialize();

			hashAlgorithm.TransformBlock(base.KeyValue, blockSizeValue << 1, blockSizeValue, null, 0);
			hashAlgorithm.TransformBlock(innerHash, 0, innerHash.Length, null, 0);
			hashAlgorithm.TransformFinalBlock(innerHash, 0, 0);

			return (base.HashValue = _HashValue_Getter(hashAlgorithm));
		}// HashFinal()

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public override void Initialize()
		{
			hashAlgorithm.Initialize();
			isHashing = false;
			isHashDirty = false;
		}// Initialize()
		#endregion overrides

		public byte[] HashInner
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get { return base.HashValue; }
		}// HashInner
	}// HMAC2 class
}//ns