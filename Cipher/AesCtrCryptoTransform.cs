using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Cipher
{
	internal static class AesConstants
	{
		public const int AES_BLOCK_SIZE = 16;
		public const string STR_AES_BLOCK_SIZE = "16";
		public const int COUNTER_SIZE = 8;
		public const string STR_COUNTER_SIZE_IN_BITS = "64";
	}

	public class AesCtrCryptoTransform : ICryptoTransform
	{
		byte[] counterBuffer_KeyStreamBuffer = new byte[AesConstants.AES_BLOCK_SIZE * 2];
		int keyStreamBytesRemaining;
		Utils.LongStruct counterStruct;

		Aes aes;
		readonly ICryptoTransform cryptoTransform;

		public bool CanReuseTransform { get { return false; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return 1; } }
		public int OutputBlockSize { get { return 1; } }

		/// <summary>ctor</summary>
		public AesCtrCryptoTransform(byte[] key, ArraySegment<byte> counterBufferSegment, Func<Aes> aesFactory = null)
		{
			if (counterBufferSegment.Count != AesConstants.AES_BLOCK_SIZE)
				ThrowNewArgumentException("counterBufferSegment.Count must be " + AesConstants.STR_AES_BLOCK_SIZE + ".");

			var aes = this.aes = aesFactory == null ? AesFactories.Aes() : aesFactory();
			(aes.Mode, aes.Padding) = (CipherMode.ECB, PaddingMode.None);

			(var counterBufferSegmentArray, var counterBufferSegmentOffset) = (counterBufferSegment.Array, counterBufferSegment.Offset);
			System.Diagnostics.Debug.Assert(AesConstants.AES_BLOCK_SIZE == 16);

			(Unsafe.As<byte, ulong>(ref this.counterBuffer_KeyStreamBuffer[0]), this.counterStruct.UlongValue) =
				Unsafe.As<byte, (ulong, ulong)>(ref counterBufferSegmentArray[counterBufferSegmentOffset]);

			if (BitConverter.IsLittleEndian)
				this.counterStruct.UlongValue = Utils.ReverseEndianness(this.counterStruct.UlongValue);

			this.cryptoTransform = aes.CreateEncryptor(rgbKey: key, rgbIV: null);
		}// ctor

		static int VECTOR_LENGTH = Vector<byte>.Count;

		#region public
		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			if (inputCount == 0) return 0;

			int i, j, remainingInputCount = inputCount;
			byte[] counterBuffer_KeyStreamBuffer = this.counterBuffer_KeyStreamBuffer; // looks dumb, but local-access is faster than field-access

			// process any available key stream first
			if (this.keyStreamBytesRemaining > 0)
			{
				j = inputCount > this.keyStreamBytesRemaining ? this.keyStreamBytesRemaining : inputCount;
				for (i = 0; i < j; ++i)
					outputBuffer[outputOffset + i] = (byte)(counterBuffer_KeyStreamBuffer[AesConstants.AES_BLOCK_SIZE * 2 - this.keyStreamBytesRemaining + i] ^ inputBuffer[inputOffset + i]);

				this.keyStreamBytesRemaining -= j;
				remainingInputCount -= j;
				if (remainingInputCount == 0) return inputCount;

				inputOffset += j;
				outputOffset += j;
			}

			int fullBlockSize = (remainingInputCount >> 4) << 4;
			int partialBlockSize = remainingInputCount - fullBlockSize;

			ref var _counterStructRef = ref this.counterStruct;

			// process full blocks, if any
			if (fullBlockSize > 0)
			{
				ref ulong counterHalf1 = ref Unsafe.As<byte, ulong>(ref counterBuffer_KeyStreamBuffer[0]);
				if (BitConverter.IsLittleEndian)
				{
					for (i = outputOffset, /* reusing j as iMax */ j = outputOffset + fullBlockSize; i < j; i += AesConstants.AES_BLOCK_SIZE)
						Unsafe.As<byte, (ulong, ulong)>(ref outputBuffer[i]) = (counterHalf1, Utils.ReverseEndianness(_counterStructRef.UlongValue++));
				}
				else
				{
					for (i = outputOffset, /* reusing j as iMax */ j = outputOffset + fullBlockSize; i < j; i += AesConstants.AES_BLOCK_SIZE)
						Unsafe.As<byte, (ulong, ulong)>(ref outputBuffer[i]) = (counterHalf1, _counterStructRef.UlongValue++);
				}

				fullBlockSize = this.cryptoTransform.TransformBlock(outputBuffer, outputOffset, fullBlockSize, outputBuffer, outputOffset);
				i = 0;

				const bool VECTORIZE = true;
				if (VECTORIZE)
				{   // vectorized xor
					int vectorLength_x2 = VECTOR_LENGTH << 1;
					int vectorLength_x4 = VECTOR_LENGTH << 2;

					int wideVectorLength;
					int vectorLimit;

					wideVectorLength = vectorLength_x4;
					vectorLimit = fullBlockSize - wideVectorLength;

					for (; i <= vectorLimit; i += wideVectorLength)
					{
						ref var destVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref outputBuffer[outputOffset + i]);
						ref var leftVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref inputBuffer[inputOffset + i]);

						destVectors.Item4 ^= leftVectors.Item4;
						destVectors.Item3 ^= leftVectors.Item3;
						destVectors.Item2 ^= leftVectors.Item2;
						destVectors.Item1 ^= leftVectors.Item1;
					}

					wideVectorLength = vectorLength_x2;
					vectorLimit = fullBlockSize - wideVectorLength;

					for (; i <= vectorLimit; i += wideVectorLength)
					{
						ref var destVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref outputBuffer[outputOffset + i]);
						ref var leftVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref inputBuffer[inputOffset + i]);

						destVectors.Item2 ^= leftVectors.Item2;
						destVectors.Item1 ^= leftVectors.Item1;
					}
				}//if (VECTORIZE)
				for (; i < fullBlockSize; ++i) outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
			}// if fullBlockSize > 0

			// process the remaining partial block, if any
			if (partialBlockSize > 0)
			{
				inputOffset += fullBlockSize;
				outputOffset += fullBlockSize;

				if (BitConverter.IsLittleEndian)
				{ /**/ Unsafe.As<byte, ulong>(ref counterBuffer_KeyStreamBuffer[8]) = Utils.ReverseEndianness(_counterStructRef.UlongValue++); }
				else { Unsafe.As<byte, ulong>(ref counterBuffer_KeyStreamBuffer[8]) = _counterStructRef.UlongValue++; }

				this.cryptoTransform.TransformBlock(counterBuffer_KeyStreamBuffer, 0, AesConstants.AES_BLOCK_SIZE, counterBuffer_KeyStreamBuffer, AesConstants.AES_BLOCK_SIZE);

				for (i = 0; i < partialBlockSize; ++i) outputBuffer[outputOffset + i] = (byte)(counterBuffer_KeyStreamBuffer[AesConstants.AES_BLOCK_SIZE + i] ^ inputBuffer[inputOffset + i]);
				this.keyStreamBytesRemaining = AesConstants.AES_BLOCK_SIZE - partialBlockSize;
			}//if partialBlockSize > 0

			return inputCount;
		}// TransformBlock()

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			byte[] outputBuffer = (inputCount == 0) ? Array.Empty<byte>() : new byte[inputCount];
			this.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
			this.Dispose();
			return outputBuffer;
		}// TransformFinalBlock()

		public void Dispose()
		{
			var aes = this.aes;
			var cryptoTransform = this.cryptoTransform;

			if (aes != null) // null aes acts as "isDisposed" flag
			{
				try
				{
					cryptoTransform.Dispose();
					aes.Dispose();
				}
				finally
				{
					var counterBuffer_KeyStreamBuffer = this.counterBuffer_KeyStreamBuffer;
					Unsafe.InitBlock(ref counterBuffer_KeyStreamBuffer[AesConstants.AES_BLOCK_SIZE], 0, (uint)AesConstants.AES_BLOCK_SIZE);
					this.aes = null;
				}
			}// if aes is not null
		}// Dispose()
		#endregion

		static void ThrowNewArgumentException(string message) => throw new ArgumentException(message);
	}// class AesCtrCryptoTransform
}//ns