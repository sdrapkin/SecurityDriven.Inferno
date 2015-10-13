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
	/// <summary>
	/// Represents a *thread-safe*, cryptographically-strong, pseudo-random number generator (based on RNGCryptoServiceProvider).
	/// 2-4 times slower than System.Random (would've been 150 times slower without buffering).
	/// </summary>
	public class CryptoRandom : Random
	{
		static readonly int CACHE_THRESHOLD; // non-buffered approach seems faster beyond this threshold (empirical experimentation).
		const int BYTE_CACHE_SIZE = 4096; // 4k buffer seems to work best (empirical experimentation). Buffer must be larger than CACHE_THRESHOLD.
		readonly byte[] _byteCache = new byte[BYTE_CACHE_SIZE];
		volatile int _byteCachePosition = BYTE_CACHE_SIZE;

		static readonly Action<byte[]> _fillBufferWithRandomBytes;
		static readonly BCrypt.BCryptAlgorithmHandle _bcryptAgorithm;

		static CryptoRandom()
		{
			try { _bcryptAgorithm = BCrypt.OpenAlgorithm(BCrypt.BCRYPT_RNG_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER); }
			catch { _bcryptAgorithm = null; }

			if (_bcryptAgorithm == null)
			{
				_fillBufferWithRandomBytes = new RNGCryptoServiceProvider().GetBytes;
				CACHE_THRESHOLD = 104;
			}
			else
			{
				_fillBufferWithRandomBytes = _bCryptGetBytes;
				CACHE_THRESHOLD = 64;
			}
		}// static ctor

		public CryptoRandom() : base(Seed: 0)
		{
			// Minimize the wasted time of calling default System.Random base ctor.
			// We can't avoid calling at least some base ctor, ie. 2~3 milliseconds are wasted anyway.
			// That's the price of inheriting from System.Random (doesn't implement an interface).
		}// ctor

		static void _bCryptGetBytes(byte[] buffer)
		{
			Debug.Assert(_bcryptAgorithm != null, "algorithm != null");
			Debug.Assert(!_bcryptAgorithm.IsClosed && !_bcryptAgorithm.IsInvalid, "!algorithm.IsClosed && !algorithm.IsInvalid");
			Debug.Assert(buffer != null, "buffer != null");

			BCrypt.ErrorCode errorCode = BCrypt.DllImportedNativeMethods.BCryptGenRandom(_bcryptAgorithm, buffer, buffer.Length, 0);
			if (errorCode != BCrypt.ErrorCode.Success) throw new CryptographicException((int)errorCode);
		}// _bCryptGetBytes()

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

		/// <summary>
		/// Fills the elements of a specified array of bytes with random numbers.
		/// </summary>
		/// <param name="buffer">An array of bytes to contain random numbers.</param>
		/// <exception cref="T:System.ArgumentNullException">
		///     <paramref name="buffer"/> is null.
		/// </exception>
		public override void NextBytes(byte[] buffer)
		{
			var bufferLength = buffer.Length;
			if (bufferLength == 0) return;
			if (bufferLength > CACHE_THRESHOLD) { _fillBufferWithRandomBytes(buffer); return; }

			while (true)
			{
				int currentByteCachePosition = Interlocked.Add(ref _byteCachePosition, bufferLength);
				if (currentByteCachePosition <= BYTE_CACHE_SIZE && currentByteCachePosition > 0)
				{
					Utils.BlockCopy(_byteCache, currentByteCachePosition - bufferLength, buffer, 0, bufferLength); return;
				}

				lock (_byteCache)
				{
					currentByteCachePosition = _byteCachePosition; // atomic read
					if (currentByteCachePosition > (BYTE_CACHE_SIZE - bufferLength) || currentByteCachePosition <= 0)
					{
						_fillBufferWithRandomBytes(_byteCache);
						_byteCachePosition = bufferLength; // atomic write
						Utils.BlockCopy(_byteCache, 0, buffer, 0, bufferLength);
						return;
					}
				}// lock
			}// while(true)
		}//NextBytes()

		/// <summary>
		/// Gets one random unsigned 32bit integer in a thread safe manner.
		/// </summary>
		uint GetRandomUInt()
		{
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
						_fillBufferWithRandomBytes(_byteCache);
						_byteCachePosition = sizeof(uint); // atomic write
						return BitConverter.ToUInt32(_byteCache, 0);
					}
				}// lock
			}// while(true)
		}//GetRandomUInt()

		/// <summary>
		/// Gets one random unsigned 64bit integer in a thread safe manner.
		/// </summary>
		ulong GetRandomULong()
		{
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
						_fillBufferWithRandomBytes(_byteCache);
						_byteCachePosition = sizeof(ulong); // atomic write
						return BitConverter.ToUInt64(_byteCache, 0);
					}
				}// lock
			}// while(true)
		}//GetRandomULong()
	}//class CryptoRandom

	#region BCrypt
	internal static class BCrypt
	{
		internal const string MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider"; // MS_PRIMITIVE_PROVIDER -- https://msdn.microsoft.com/en-us/library/windows/desktop/aa375479(v=vs.85).aspx
		internal const string BCRYPT_RNG_ALGORITHM = "RNG"; // BCRYPT_RNG_ALGORITHM -- https://msdn.microsoft.com/en-us/library/windows/desktop/aa375534(v=vs.85).aspx

		/// <summary>
		/// Open a handle to a BCrypt algorithm provider.
		/// </summary>
		internal static BCryptAlgorithmHandle OpenAlgorithm(string algorithm, string implementation)
		{
			Debug.Assert(!string.IsNullOrEmpty(algorithm), "!String.IsNullOrEmpty(algorithm)");
			Debug.Assert(!string.IsNullOrEmpty(implementation), "!String.IsNullOrEmpty(implementation)");

			BCryptAlgorithmHandle algorithmHandle = null;
			ErrorCode error = DllImportedNativeMethods.BCryptOpenAlgorithmProvider(out algorithmHandle, algorithm, implementation, AlgorithmProviderOptions.None);
			if (error != ErrorCode.Success) throw new CryptographicException(error.ToString());
			return algorithmHandle;
		}

		internal sealed class BCryptAlgorithmHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
		{
			BCryptAlgorithmHandle() : base(ownsHandle: true) { }
			protected override bool ReleaseHandle()
			{
				return DllImportedNativeMethods.BCryptCloseAlgorithmProvider(handle, AlgorithmProviderOptions.None) == ErrorCode.Success;
			}
		}// class BCryptAlgorithmHandle

		/// <summary>
		/// Result codes from BCrypt APIs.
		/// </summary>
		internal enum ErrorCode
		{
			Success = 0x00000000,                                       // STATUS_SUCCESS
			AuthenticationTagMismatch = unchecked((int)0xC000A002),     // STATUS_AUTH_TAG_MISMATCH
			BufferToSmall = unchecked((int)0xC0000023)                  // STATUS_BUFFER_TOO_SMALL
		}// enum ErrorCode

		/// <summary>
		/// Flags for BCryptOpenAlgorithmProvider.
		/// </summary>
		[Flags] internal enum AlgorithmProviderOptions { None = 0x00000000 }

		internal static class DllImportedNativeMethods
		{
			const string bcrypt_dll = "bcrypt.dll";

			[DllImport(bcrypt_dll)]
			// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375458(v=vs.85).aspx
			internal static extern ErrorCode BCryptGenRandom(
				BCryptAlgorithmHandle hAlgorithm,
				[In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbBuffer,
				int cbBuffer,
				int dwFlags);

			[DllImport(bcrypt_dll)]
			// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375479(v=vs.85).aspx
			internal static extern ErrorCode BCryptOpenAlgorithmProvider(
				[Out] out BCryptAlgorithmHandle phAlgorithm,
				[MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
				[MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
				AlgorithmProviderOptions dwFlags);

			[DllImport(bcrypt_dll)]
			// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375377(v=vs.85).aspx
			internal static extern ErrorCode BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, AlgorithmProviderOptions dwFlags);
		}// class DllImportedNativeMathods
	}// class BCrypt
	#endregion
}//ns