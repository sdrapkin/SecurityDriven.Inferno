using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Kdf
{
	using Mac;
	using Extensions;

	public class PBKDF2 : DeriveBytes
	{
		// Fields
		static readonly CryptoRandom rng = new CryptoRandom();
		int BlockSize, endIndex, startIndex, iterations;
		uint block;
		byte[] buffer, salt;
		HMAC hmac;
		HMAC2 hmac2;

		/// <summary>
		/// Default iteration count.
		/// </summary>
		public const int DefaultIterations = 10000;


		/// <summary>
		/// ctor
		/// </summary>
		/// <param name="hmacFactory">hmacFactory</param>
		/// <param name="password">password</param>
		/// <param name="saltSize">saltSize</param>
		public PBKDF2(Func<HMAC> hmacFactory, string password, int saltSize)
			: this(hmacFactory, password, saltSize, DefaultIterations)
		{
		}//ctor

		/// <summary>
		/// ctor
		/// </summary>
		/// <param name="hmacFactory">hmacFactory</param>
		/// <param name="password">password</param>
		/// <param name="salt">salt</param>
		public PBKDF2(Func<HMAC> hmacFactory, string password, byte[] salt)
			: this(hmacFactory, password, salt, DefaultIterations)
		{
		}//ctor

		/// <summary>
		/// ctor
		/// </summary>
		/// <param name="hmacFactory">hmacFactory</param>
		/// <param name="password">password</param>
		/// <param name="salt">salt</param>
		/// <param name="iterations">iterations</param>
		public PBKDF2(Func<HMAC> hmacFactory, string password, byte[] salt, int iterations)
			: this(hmacFactory, password.ToBytes(), salt, iterations)
		{
		}//ctor

		/// <summary>
		/// ctor
		/// </summary>
		/// <param name="hmacFactory">hmacFactory</param>
		/// <param name="password">password</param>
		/// <param name="saltSize">saltSize</param>
		/// <param name="iterations">iterations</param>
		public PBKDF2(Func<HMAC> hmacFactory, string password, int saltSize, int iterations)
			: this(hmacFactory, password.ToBytes(), GenerateSalt(saltSize), iterations)
		{
		}//ctor

		/// <summary>
		/// ctor
		/// </summary>
		/// <param name="hmacFactory">hmacFactory</param>
		/// <param name="password">password</param>
		/// <param name="salt">salt</param>
		/// <param name="iterations">iterations</param>
		public PBKDF2(Func<HMAC> hmacFactory, byte[] password, byte[] salt, int iterations)
		{
			this.Salt = salt;
			this.IterationCount = iterations;
			this.hmac = hmacFactory();
			this.hmac2 = hmac as HMAC2;
			this.hmac.Key = password;
			this.BlockSize = hmac.HashSize / 8;
			this.Initialize();
		}//ctor

		static byte[] GenerateSalt(int saltSize)
		{
			if (saltSize < 0)
				throw new ArgumentOutOfRangeException(nameof(saltSize));

			byte[] data = new byte[saltSize];
			rng.NextBytes(data, 0, data.Length);
			return data;
		}//GenerateSalt()

		/// <summary>
		/// Releases the unmanaged resources used, and optionally releases the managed resources.
		/// </summary>
		/// <param name="disposing">true to release both managed and unmanaged resources; false to release only managed resources.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (this.hmac != null)
				{
					this.hmac.Dispose();
				}
				if (this.buffer != null)
				{
					Array.Clear(this.buffer, 0, this.buffer.Length);
				}
				if (this.salt != null)
				{
					Array.Clear(this.salt, 0, this.salt.Length);
				}
			}
		}//Dispose()

		byte[] inputBuffer = new byte[4];
		byte[] Func()
		{
			// localize members
			var _inputBuffer = this.inputBuffer;
			var _hmac = this.hmac;
			var _hmac2 = this.hmac2;

			new Utils.IntStruct { UintValue = this.block }.ToBEBytes(_inputBuffer);
			this.hmac.TransformBlock(inputBuffer: this.salt, inputOffset: 0, inputCount: this.salt.Length, outputBuffer: null, outputOffset: 0);
			this.hmac.TransformBlock(inputBuffer: _inputBuffer, inputOffset: 0, inputCount: _inputBuffer.Length, outputBuffer: null, outputOffset: 0);
			this.hmac.TransformFinalBlock(inputBuffer: _inputBuffer, inputOffset: 0, inputCount: 0);
			byte[] hash = this.hmac.Hash; // creates a copy
			this.hmac.Initialize();
			byte[] buffer3 = hash;

			for (int i = 2, blockSize = BlockSize, j = this.iterations; i <= j; i++)
			{
				if (_hmac2 != null)
				{
					_hmac2.TransformBlock(hash, 0, blockSize, null, 0);
					_hmac2.TransformFinalBlock(hash, 0, 0);
					hash = _hmac2.HashInner;
				}
				else hash = _hmac.ComputeHash(hash);
				Utils.Xor(dest: buffer3, destOffset: 0, left: hash, leftOffset: 0, byteCount: blockSize);
			}
			this.block++;
			return buffer3;
		}

		// Properties
		/// <summary>
		/// Gets or sets the number of iterations for the operation.
		/// </summary>
		public int IterationCount
		{
			get
			{
				return this.iterations;
			}
			set
			{
				if (value <= 0)
				{
					throw new ArgumentOutOfRangeException(nameof(value));
				}
				this.iterations = value;
				this.Initialize();
			}
		}

		/// <summary>
		/// Gets or sets the key salt value for the operation.
		/// </summary>
		public byte[] Salt
		{
			get
			{
				return this.salt.CloneBytes();
			}
			set
			{
				if (value == null)
				{
					throw new ArgumentNullException(nameof(value));
				}
				if (value.Length < 8)
				{
					throw new ArgumentException("Salt is not at least 8 bytes.");
				}
				this.salt = value.CloneBytes();
				this.Initialize();
			}
		}

		// Methods
		/// <summary>
		/// Returns pseudo-random bytes.
		/// </summary>
		/// <param name="cb">The number of pseudo-random bytes to generate.</param>
		/// <returns></returns>
		public override byte[] GetBytes(int cb)
		{
			if (cb <= 0)
			{
				throw new ArgumentOutOfRangeException(nameof(cb), "Positive number required.");
			}
			byte[] dst = new byte[cb];
			int dstOffsetBytes = 0;
			int byteCount = this.endIndex - this.startIndex;
			if (byteCount > 0)
			{
				if (cb < byteCount)
				{
					Buffer.BlockCopy(this.buffer, this.startIndex, dst, 0, cb);
					this.startIndex += cb;
					return dst;
				}
				Buffer.BlockCopy(this.buffer, this.startIndex, dst, 0, byteCount);
				this.startIndex = this.endIndex = 0;
				dstOffsetBytes += byteCount;
			}//if

			while (dstOffsetBytes < cb)
			{
				byte[] src = this.Func();
				int num3 = cb - dstOffsetBytes;
				if (num3 > BlockSize)
				{
					Buffer.BlockCopy(src, 0, dst, dstOffsetBytes, BlockSize);
					dstOffsetBytes += BlockSize;
				}
				else
				{
					Buffer.BlockCopy(src, 0, dst, dstOffsetBytes, num3);
					dstOffsetBytes += num3;
					Buffer.BlockCopy(src, num3, this.buffer, this.startIndex, BlockSize - num3);
					this.endIndex += BlockSize - num3;
					return dst;
				}
			}//while
			return dst;
		}//GetBytes()

		void Initialize()
		{
			if (this.buffer != null)
			{
				Array.Clear(this.buffer, 0, this.buffer.Length);
			}
			this.buffer = new byte[BlockSize];
			this.block = 1;
			this.startIndex = this.endIndex = 0;
		}

		/// <summary>
		/// Resets the state.
		/// </summary>
		/// <remarks>
		/// This method is automatically called if the salt or iteration count is modified.
		/// </remarks>
		public override void Reset()
		{
			this.Initialize();
		}
	}//class PBKDF2
}//ns