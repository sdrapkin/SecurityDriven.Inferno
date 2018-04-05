using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Cipher
{
	using Extensions;

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
				throw new ArgumentException("counterBufferSegment.Count must be " + AesConstants.STR_AES_BLOCK_SIZE + ".");

			var aes = aesFactory == null ? AesFactories.Aes() : aesFactory();

			aes.Mode = CipherMode.ECB;
			aes.Padding = PaddingMode.None;

			var counterBufferSegmentArray = counterBufferSegment.Array;
			var counterBufferSegmentOffset = counterBufferSegment.Offset;

			byte[] counterBuffer_KeyStreamBuffer = this.counterBuffer_KeyStreamBuffer; // looks dumb, but local-access is faster than field-access

			System.Diagnostics.Debug.Assert(AesConstants.AES_BLOCK_SIZE == 16);

			//Utils.BlockCopy(counterBufferSegment.Array, counterBufferSegment.Offset, counterBuffer_KeyStreamBuffer, 0, AesConstants.AES_BLOCK_SIZE);
			counterBuffer_KeyStreamBuffer[00] = counterBufferSegmentArray[counterBufferSegmentOffset + 00];
			counterBuffer_KeyStreamBuffer[01] = counterBufferSegmentArray[counterBufferSegmentOffset + 01];
			counterBuffer_KeyStreamBuffer[02] = counterBufferSegmentArray[counterBufferSegmentOffset + 02];
			counterBuffer_KeyStreamBuffer[03] = counterBufferSegmentArray[counterBufferSegmentOffset + 03];
			counterBuffer_KeyStreamBuffer[04] = counterBufferSegmentArray[counterBufferSegmentOffset + 04];
			counterBuffer_KeyStreamBuffer[05] = counterBufferSegmentArray[counterBufferSegmentOffset + 05];
			counterBuffer_KeyStreamBuffer[06] = counterBufferSegmentArray[counterBufferSegmentOffset + 06];
			counterBuffer_KeyStreamBuffer[07] = counterBufferSegmentArray[counterBufferSegmentOffset + 07];
			counterBuffer_KeyStreamBuffer[08] = counterBufferSegmentArray[counterBufferSegmentOffset + 08];
			counterBuffer_KeyStreamBuffer[09] = counterBufferSegmentArray[counterBufferSegmentOffset + 09];
			counterBuffer_KeyStreamBuffer[10] = counterBufferSegmentArray[counterBufferSegmentOffset + 10];
			counterBuffer_KeyStreamBuffer[11] = counterBufferSegmentArray[counterBufferSegmentOffset + 11];
			counterBuffer_KeyStreamBuffer[12] = counterBufferSegmentArray[counterBufferSegmentOffset + 12];
			counterBuffer_KeyStreamBuffer[13] = counterBufferSegmentArray[counterBufferSegmentOffset + 13];
			counterBuffer_KeyStreamBuffer[14] = counterBufferSegmentArray[counterBufferSegmentOffset + 14];
			counterBuffer_KeyStreamBuffer[15] = counterBufferSegmentArray[counterBufferSegmentOffset + 15];

			this.cryptoTransform = aes.CreateEncryptor(rgbKey: key, rgbIV: null);
			this.aes = aes;
		}// ctor

		#region public
		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			if (inputCount == 0) return 0;

			int i, j, k, remainingInputCount = inputCount;
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

			int partialBlockSize = remainingInputCount % AesConstants.AES_BLOCK_SIZE;
			int fullBlockSize = remainingInputCount & (-AesConstants.AES_BLOCK_SIZE); // remainingInputCount - partialBlockSize;

			// process full blocks, if any
			if (fullBlockSize > 0)
			{
				for (i = outputOffset, /* reusing k as iMax */ k = outputOffset + fullBlockSize; i < k; i += AesConstants.AES_BLOCK_SIZE)
				{
					//Utils.BlockCopy(counterBuffer_KeyStreamBuffer, 0, outputBuffer, i, AesConstants.AES_BLOCK_SIZE);
					outputBuffer[i + 00] = counterBuffer_KeyStreamBuffer[00];
					outputBuffer[i + 01] = counterBuffer_KeyStreamBuffer[01];
					outputBuffer[i + 02] = counterBuffer_KeyStreamBuffer[02];
					outputBuffer[i + 03] = counterBuffer_KeyStreamBuffer[03];
					outputBuffer[i + 04] = counterBuffer_KeyStreamBuffer[04];
					outputBuffer[i + 05] = counterBuffer_KeyStreamBuffer[05];
					outputBuffer[i + 06] = counterBuffer_KeyStreamBuffer[06];
					outputBuffer[i + 07] = counterBuffer_KeyStreamBuffer[07];
					outputBuffer[i + 08] = counterBuffer_KeyStreamBuffer[08];
					outputBuffer[i + 09] = counterBuffer_KeyStreamBuffer[09];
					outputBuffer[i + 10] = counterBuffer_KeyStreamBuffer[10];
					outputBuffer[i + 11] = counterBuffer_KeyStreamBuffer[11];
					outputBuffer[i + 12] = counterBuffer_KeyStreamBuffer[12];
					outputBuffer[i + 13] = counterBuffer_KeyStreamBuffer[13];
					outputBuffer[i + 14] = counterBuffer_KeyStreamBuffer[14];
					outputBuffer[i + 15] = counterBuffer_KeyStreamBuffer[15];

					for (j = AesConstants.AES_BLOCK_SIZE - 1; j >= AesConstants.AES_BLOCK_SIZE - AesConstants.COUNTER_SIZE; --j) if (++counterBuffer_KeyStreamBuffer[j] != 0) break;
				}

				fullBlockSize = this.cryptoTransform.TransformBlock(outputBuffer, outputOffset, fullBlockSize, outputBuffer, outputOffset);

				//Utils.Xor(outputBuffer, outputOffset, inputBuffer, inputOffset, fullBlockSize);
				/* vectorized xor
				{
					const int vectorLength = 32;
					i = 0;
					for (i = 0; i + vectorLength < fullBlockSize; i += vectorLength)
					{
						var destVector = new Vector<byte>(outputBuffer, outputOffset + i);
						var leftVector = new Vector<byte>(inputBuffer, inputOffset + i);
						Vector.Xor(destVector, leftVector).CopyTo(outputBuffer, outputOffset + i);
					}
				}
				*/

				{
					if (((outputOffset | inputOffset) & 7) == 0) // all offsets must be multiples of 8 for long-sized xor
					{
						long[] destUnionLongs = new Utils.Union { Bytes = outputBuffer }.Longs, leftUnionLongs = new Utils.Union { Bytes = inputBuffer }.Longs;
						int longDestOffset = outputOffset >> 3, longLeftOffset = inputOffset >> 3, longCount = fullBlockSize >> 3;
						for (i = 0; i < longCount; ++i) destUnionLongs[longDestOffset + i] ^= leftUnionLongs[longLeftOffset + i];
						i = longCount << 3;
					}
				}

				for (; i < fullBlockSize; ++i) outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
			}// if fullBlockSize > 0

			// process the remaining partial block, if any
			if (partialBlockSize > 0)
			{
				inputOffset += fullBlockSize;
				outputOffset += fullBlockSize;

				this.cryptoTransform.TransformBlock(counterBuffer_KeyStreamBuffer, 0, AesConstants.AES_BLOCK_SIZE, counterBuffer_KeyStreamBuffer, AesConstants.AES_BLOCK_SIZE);
				for (j = AesConstants.AES_BLOCK_SIZE - 1; j >= AesConstants.AES_BLOCK_SIZE - AesConstants.COUNTER_SIZE; --j) if (++counterBuffer_KeyStreamBuffer[j] != 0) break;
				for (i = 0; i < partialBlockSize; ++i) outputBuffer[outputOffset + i] = (byte)(counterBuffer_KeyStreamBuffer[AesConstants.AES_BLOCK_SIZE + i] ^ inputBuffer[inputOffset + i]);
				this.keyStreamBytesRemaining = AesConstants.AES_BLOCK_SIZE - partialBlockSize;
			}

			return inputCount;
		}// TransformBlock()

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			byte[] outputBuffer = new byte[inputCount];
			this.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
			this.Dispose();
			return outputBuffer;
		}// TransformFinalBlock()

		public void Dispose()
		{
			if (this.aes != null) // null aes acts as "isDisposed" flag
			{
				try
				{
					this.cryptoTransform.Dispose();
					this.aes.Dispose();
				}
				finally
				{
					Array.Clear(this.counterBuffer_KeyStreamBuffer, 0, AesConstants.AES_BLOCK_SIZE * 2);
					this.aes = null;
				}
			}// if aes is not null
		}// Dispose()
		#endregion
	}// class AesCtrCryptoTransform
}//ns