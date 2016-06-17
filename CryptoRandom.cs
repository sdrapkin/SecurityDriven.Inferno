using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace SecurityDriven.Inferno
{
	/* Original version by Stephen Toub and Shawn Farkas.
	 * http://msdn.microsoft.com/en-us/magazine/cc163367.aspx
	 * Buffered concept from here: https://gist.github.com/1017834
	 */
	/// <summary>Implements a fast, *thread-safe*, cryptographically-strong pseudo-random number generator.</summary>
	public class CryptoRandom : Random
	{
		const int CACHE_THRESHOLD = 64; // 64 yields ~ 1/3 perf ratio between cache hit and BCrypt call to repopulate the cache
		const int BYTE_CACHE_SIZE = 4096; // 4k buffer seems to work best (empirical experimentation). Buffer must be larger than CACHE_THRESHOLD.
		readonly byte[] _byteCache = new byte[BYTE_CACHE_SIZE];
		volatile int _byteCachePosition = BYTE_CACHE_SIZE;

		static CryptoRandom()
		{
			SanityCheck();
		}// static ctor

		public CryptoRandom() : base(Seed: 0)
		{
			// Minimize the wasted time of calling default System.Random base ctor.
			// We can't avoid calling at least some base ctor, ie. 2~3 milliseconds are wasted anyway.
			// That's the price of inheriting from System.Random (doesn't implement an interface).
		}// ctor

		static void SanityCheck()
		{
			var testBuffer = new byte[BYTE_CACHE_SIZE];
			int status, i, j;

			status = (int)BCrypt.BCryptGenRandom(testBuffer, BYTE_CACHE_SIZE / 2);
			if (status != (int)BCrypt.NTSTATUS.STATUS_SUCCESS) throw new CryptographicException(status);

			for (i = BYTE_CACHE_SIZE / 2; i < BYTE_CACHE_SIZE; ++i)
				if (testBuffer[i] != 0) throw new CryptographicException("CryptoRandom failed sanity check #1.");

			for (i = 0, status = 0, j = BYTE_CACHE_SIZE / 2; i < j; ++i) status |= testBuffer[i];
			if (status == 0) throw new CryptographicException("CryptoRandom failed sanity check #2.");
		}// SanityCheck()

		#region NextLong()
		/// <summary>
		/// Returns a nonnegative random number.
		/// </summary>
		/// <returns>
		/// A 64-bit signed integer greater than or equal to zero and less than <see cref="F:System.Int64.MaxValue"/>.
		/// </returns>
		public long NextLong()
		{
			// Mask away the sign bit so that we always return nonnegative integers
			return (long)GetRandomULong() & 0x7FFFFFFFFFFFFFFF;
		}//NextLong()

		/// <summary>
		/// Returns a nonnegative random number less than the specified maximum.
		/// </summary>
		/// <param name="maxValue">The exclusive upper bound of the random number to be generated. <paramref name="maxValue"/> must be greater than or equal to zero.</param>
		/// <returns>
		/// A 64-bit signed integer greater than or equal to zero, and less than <paramref name="maxValue"/>; that is, the range of return values ordinarily includes zero but not <paramref name="maxValue"/>. However, if <paramref name="maxValue"/> equals zero, <paramref name="maxValue"/> is returned.
		/// </returns>
		/// <exception cref="T:System.ArgumentOutOfRangeException">
		///     <paramref name="maxValue"/> is less than zero.
		/// </exception>
		public long NextLong(long maxValue)
		{
			if (maxValue < 0)
				throw new ArgumentOutOfRangeException("maxValue");

			return NextLong(0, maxValue);
		}//NextLong()

		/// <summary>
		/// Returns a random number within a specified range.
		/// </summary>
		/// <param name="minValue">The inclusive lower bound of the random number returned.</param>
		/// <param name="maxValue">The exclusive upper bound of the random number returned. <paramref name="maxValue"/> must be greater than or equal to <paramref name="minValue"/>.</param>
		/// <returns>
		/// A 64-bit signed integer greater than or equal to <paramref name="minValue"/> and less than <paramref name="maxValue"/>; that is, the range of return values includes <paramref name="minValue"/> but not <paramref name="maxValue"/>. If <paramref name="minValue"/> equals <paramref name="maxValue"/>, <paramref name="minValue"/> is returned.
		/// </returns>
		/// <exception cref="T:System.ArgumentOutOfRangeException">
		///     <paramref name="minValue"/> is greater than <paramref name="maxValue"/>.
		/// </exception>
		public long NextLong(long minValue, long maxValue)
		{
			if (minValue == maxValue)
				return minValue;

			if (minValue > maxValue)
				throw new ArgumentOutOfRangeException("minValue");

			ulong diff = decimal.ToUInt64((decimal)maxValue - minValue);
			ulong upperBound = ulong.MaxValue / diff * diff;

			ulong ul;
			do
			{
				ul = GetRandomULong();
			} while (ul >= upperBound);
			return decimal.ToInt64((decimal)minValue + ul % diff);
		}//NextLong()
		#endregion

		#region Next()
		/// <summary>
		/// Returns a nonnegative random number.
		/// </summary>
		/// <returns>
		/// A 32-bit signed integer greater than or equal to zero and less than <see cref="F:System.Int32.MaxValue"/>.
		/// </returns>
		public override int Next()
		{
			// Mask away the sign bit so that we always return nonnegative integers
			return (int)GetRandomUInt() & 0x7FFFFFFF;
		}//Next()

		/// <summary>
		/// Returns a nonnegative random number less than the specified maximum.
		/// </summary>
		/// <param name="maxValue">The exclusive upper bound of the random number to be generated. <paramref name="maxValue"/> must be greater than or equal to zero.</param>
		/// <returns>
		/// A 32-bit signed integer greater than or equal to zero, and less than <paramref name="maxValue"/>; that is, the range of return values ordinarily includes zero but not <paramref name="maxValue"/>. However, if <paramref name="maxValue"/> equals zero, <paramref name="maxValue"/> is returned.
		/// </returns>
		/// <exception cref="T:System.ArgumentOutOfRangeException">
		///     <paramref name="maxValue"/> is less than zero.
		/// </exception>
		public override int Next(int maxValue)
		{
			if (maxValue < 0)
				throw new ArgumentOutOfRangeException("maxValue");

			return Next(0, maxValue);
		}//Next()

		/// <summary>
		/// Returns a random number within a specified range.
		/// </summary>
		/// <param name="minValue">The inclusive lower bound of the random number returned.</param>
		/// <param name="maxValue">The exclusive upper bound of the random number returned. <paramref name="maxValue"/> must be greater than or equal to <paramref name="minValue"/>.</param>
		/// <returns>
		/// A 32-bit signed integer greater than or equal to <paramref name="minValue"/> and less than <paramref name="maxValue"/>; that is, the range of return values includes <paramref name="minValue"/> but not <paramref name="maxValue"/>. If <paramref name="minValue"/> equals <paramref name="maxValue"/>, <paramref name="minValue"/> is returned.
		/// </returns>
		/// <exception cref="T:System.ArgumentOutOfRangeException">
		///     <paramref name="minValue"/> is greater than <paramref name="maxValue"/>.
		/// </exception>
		public override int Next(int minValue, int maxValue)
		{
			if (minValue == maxValue)
				return minValue;

			if (minValue > maxValue)
				throw new ArgumentOutOfRangeException("minValue");

			long diff = (long)maxValue - minValue;
			long upperBound = uint.MaxValue / diff * diff;

			uint ui;
			do
			{
				ui = GetRandomUInt();
			} while (ui >= upperBound);
			return (int)(minValue + (ui % diff));
		}//Next()
		#endregion

		/// <summary>
		/// Returns a random number between 0.0 and 1.0.
		/// </summary>
		/// <returns>
		/// A double-precision floating point number greater than or equal to 0.0, and less than 1.0.
		/// </returns>
		public override double NextDouble()
		{
			const double max = 1.0 + uint.MaxValue;
			return GetRandomUInt() / max;
		}//NextDouble()

		/// <summary>
		/// Returns a new count-sized byte array filled with random bytes.
		/// </summary>
		/// <param name="count">Array length.</param>
		/// <returns>Random byte array.</returns>
		public byte[] NextBytes(int count)
		{
			byte[] bytes = new byte[count];
			this.NextBytes(bytes);
			return bytes;
		}//NextBytes()

		/// <summary>Fills the elements of a specified array of bytes with random numbers.</summary>
		/// <param name="buffer">The array to fill with cryptographically strong random bytes.</param>
		/// <exception cref="T:System.ArgumentNullException">
		///     <paramref name="buffer"/> is null.
		/// </exception>
		public override void NextBytes(byte[] buffer)
		{
			NextBytes(buffer, 0, buffer.Length);
		}//NextBytes()

		/// <summary>
		/// Fills the specified byte array with a cryptographically strong random sequence of values.
		/// </summary>
		/// <param name="buffer">An array of bytes to contain random numbers.</param>
		/// <param name="offset"></param>
		/// <param name="count">Number of bytes to generate (must be lte buffer.Length).</param>
		/// <exception cref="T:System.ArgumentNullException">
		///     <paramref name="buffer"/> is null.
		/// </exception>
		public void NextBytes(byte[] buffer, int offset, int count)
		{
			var checkedBufferSegment = new ArraySegment<byte>(buffer, offset, count); // bounds-validation happens here
			if (count == 0) return;
			NextBytesInternal(checkedBufferSegment);
		}

		void NextBytesInternal(ArraySegment<byte> bufferSegment)
		{
			BCrypt.NTSTATUS status;
			var buffer = bufferSegment.Array;
			var offset = bufferSegment.Offset;
			var count = bufferSegment.Count;

			if (count > CACHE_THRESHOLD)
			{
				status = (offset == 0) ? BCrypt.BCryptGenRandom(buffer, count) : BCrypt.BCryptGenRandom_PinnedBuffer(buffer, offset, count);
				if (status == BCrypt.NTSTATUS.STATUS_SUCCESS) return;
				throw new CryptographicException((int)status);
			}

			while (true)
			{
				int currentByteCachePosition = Interlocked.Add(ref _byteCachePosition, count);
				if (currentByteCachePosition <= BYTE_CACHE_SIZE && currentByteCachePosition > 0)
				{
					Utils.BlockCopy(_byteCache, currentByteCachePosition - count, buffer, 0, count);
					return;
				}

				lock (_byteCache)
				{
					currentByteCachePosition = _byteCachePosition; // atomic read
					if (currentByteCachePosition > (BYTE_CACHE_SIZE - count) || currentByteCachePosition <= 0)
					{
						status = BCrypt.BCryptGenRandom(_byteCache, BYTE_CACHE_SIZE);
						if (status == BCrypt.NTSTATUS.STATUS_SUCCESS)
						{
							_byteCachePosition = count; // atomic write
							Utils.BlockCopy(_byteCache, 0, buffer, 0, count);
							return;
						}

						// defensive logic to prevent _byteCachePosition from wrapping into valid range due to BCryptGenRandom failures
						if (currentByteCachePosition > BYTE_CACHE_SIZE || currentByteCachePosition < 0) _byteCachePosition = BYTE_CACHE_SIZE;

						throw new CryptographicException((int)status);
					}// if outside the valid range
				}// lock
			}// while(true)
		}//NextBytes()

		/// <summary>
		/// Gets one random unsigned 32bit integer in a thread safe manner.
		/// </summary>
		uint GetRandomUInt()
		{
			BCrypt.NTSTATUS status;
			while (true)
			{
				int currentByteCachePosition = Interlocked.Add(ref _byteCachePosition, sizeof(uint));
				if (currentByteCachePosition <= BYTE_CACHE_SIZE && currentByteCachePosition > 0)
					return BitConverter.ToUInt32(_byteCache, currentByteCachePosition - sizeof(uint));

				lock (_byteCache)
				{
					currentByteCachePosition = _byteCachePosition; // atomic read
					if (currentByteCachePosition > (BYTE_CACHE_SIZE - sizeof(uint)) || currentByteCachePosition <= 0)
					{
						status = BCrypt.BCryptGenRandom(_byteCache, BYTE_CACHE_SIZE);
						if (status == BCrypt.NTSTATUS.STATUS_SUCCESS)
						{
							_byteCachePosition = sizeof(uint); // atomic write
							return BitConverter.ToUInt32(_byteCache, 0);
						}

						// defensive logic to prevent _byteCachePosition from wrapping into valid range due to BCryptGenRandom failures
						if (currentByteCachePosition > BYTE_CACHE_SIZE || currentByteCachePosition < 0) _byteCachePosition = BYTE_CACHE_SIZE;

						throw new CryptographicException((int)status);
					}// if outside the valid range
				}// lock
			}// while(true)
		}//GetRandomUInt()

		/// <summary>
		/// Gets one random unsigned 64bit integer in a thread safe manner.
		/// </summary>
		ulong GetRandomULong()
		{
			BCrypt.NTSTATUS status;
			while (true)
			{
				int currentByteCachePosition = Interlocked.Add(ref _byteCachePosition, sizeof(ulong));
				if (currentByteCachePosition <= BYTE_CACHE_SIZE && currentByteCachePosition > 0)
					return BitConverter.ToUInt64(_byteCache, currentByteCachePosition - sizeof(ulong));

				lock (_byteCache)
				{
					currentByteCachePosition = _byteCachePosition; // atomic read
					if (currentByteCachePosition > (BYTE_CACHE_SIZE - sizeof(ulong)) || currentByteCachePosition <= 0)
					{
						status = BCrypt.BCryptGenRandom(_byteCache, BYTE_CACHE_SIZE);
						if (status == BCrypt.NTSTATUS.STATUS_SUCCESS)
						{
							_byteCachePosition = sizeof(ulong); // atomic write
							return BitConverter.ToUInt64(_byteCache, 0);
						}

						// defensive logic to prevent _byteCachePosition from wrapping into valid range due to BCryptGenRandom failures
						if (currentByteCachePosition > BYTE_CACHE_SIZE || currentByteCachePosition < 0) _byteCachePosition = BYTE_CACHE_SIZE;

						throw new CryptographicException((int)status);
					}// if outside the valid range
				}// lock
			}// while(true)
		}//GetRandomULong()
	}//class CryptoRandom

	#region BCrypt
	// https://github.com/dotnet/corefx/blob/879182b657e7d18117c6d537b85c92841618b119/src/Common/src/Interop/Windows/BCrypt/Interop.BCryptGenRandom.cs
	internal static class BCrypt
	{
		const string bcrypt_dll = "bcrypt.dll";
		const int BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002; // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375458.aspx

		// https://msdn.microsoft.com/en-ca/library/cc704588.aspx
		internal enum NTSTATUS : uint { STATUS_SUCCESS = 0x0 } // and many other "failure" statuses we have no need to differentiate

		internal static NTSTATUS BCryptGenRandom(byte[] pbBuffer, int cbBuffer)
		{
			Debug.Assert(pbBuffer != null);
			Debug.Assert(cbBuffer >= 0 && cbBuffer <= pbBuffer.Length);
			return BCryptGenRandom(IntPtr.Zero, pbBuffer, cbBuffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		}

		internal static NTSTATUS BCryptGenRandom_PinnedBuffer(byte[] pbBuffer, int obBuffer, int cbBuffer)
		{
			Debug.Assert(pbBuffer != null);
			Debug.Assert(cbBuffer >= 0 && obBuffer >= 0 && (obBuffer + cbBuffer) <= pbBuffer.Length);

			GCHandle pinnedBufferHandle = default(GCHandle);
			NTSTATUS status;
			try
			{
				pinnedBufferHandle = GCHandle.Alloc(pbBuffer, GCHandleType.Pinned);
				status = BCrypt.BCryptGenRandom(IntPtr.Zero, pinnedBufferHandle.AddrOfPinnedObject() + obBuffer, cbBuffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
			}
			finally
			{
				if (pinnedBufferHandle.IsAllocated) pinnedBufferHandle.Free();
			}

			return status;
		}// BCryptGenRandom()

		[DllImport(bcrypt_dll, CharSet = CharSet.Unicode)]
		static extern NTSTATUS BCryptGenRandom(IntPtr hAlgorithm, [In, Out] byte[] pbBuffer, int cbBuffer, int dwFlags);

		[DllImport(bcrypt_dll, CharSet = CharSet.Unicode)]
		static extern NTSTATUS BCryptGenRandom(IntPtr hAlgorithm, [In, Out] IntPtr pbBuffer, int cbBuffer, int dwFlags);
	}// class BCrypt
	#endregion
}//ns