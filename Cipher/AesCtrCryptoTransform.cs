using System;
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

			this.aes = aesFactory == null ? AesFactories.Aes() : aesFactory();
			this.aes.Mode = CipherMode.ECB;
			this.aes.Padding = PaddingMode.None;

			Utils.BlockCopy(counterBufferSegment.Array, counterBufferSegment.Offset, counterBuffer_KeyStreamBuffer, 0, AesConstants.AES_BLOCK_SIZE);
			this.cryptoTransform = aes.CreateEncryptor(rgbKey: key, rgbIV: null);
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

				inputOffset += j;
				outputOffset += j;
				this.keyStreamBytesRemaining -= j;
				remainingInputCount -= j;

				if (remainingInputCount == 0) return inputCount;
			}

			int partialBlockSize = remainingInputCount % AesConstants.AES_BLOCK_SIZE;
			int fullBlockSize = remainingInputCount & (-AesConstants.AES_BLOCK_SIZE); // remainingInputCount - partialBlockSize;

			// process full blocks, if any
			if (fullBlockSize > 0)
			{
				for (i = outputOffset, /* reusing k as iMax */ k = outputOffset + fullBlockSize; i < k; i += AesConstants.AES_BLOCK_SIZE)
				{
					Utils.BlockCopy(counterBuffer_KeyStreamBuffer, 0, outputBuffer, i, AesConstants.AES_BLOCK_SIZE);
					for (j = AesConstants.AES_BLOCK_SIZE - 1; j >= AesConstants.AES_BLOCK_SIZE - AesConstants.COUNTER_SIZE; --j) if (++counterBuffer_KeyStreamBuffer[j] != 0) break;
				}

				fullBlockSize = this.cryptoTransform.TransformBlock(outputBuffer, outputOffset, fullBlockSize, outputBuffer, outputOffset);
				Utils.Xor(outputBuffer, outputOffset, inputBuffer, inputOffset, fullBlockSize);
			}

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
			}
		}// Dispose()
		#endregion
	}// class AesCtrCryptoTransform
}//ns