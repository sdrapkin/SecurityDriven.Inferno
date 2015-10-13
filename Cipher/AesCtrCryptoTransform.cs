using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;

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
		static readonly ThreadLocal<byte[]> _counterBuffer = new ThreadLocal<byte[]>(() => new byte[AesConstants.AES_BLOCK_SIZE]);

		Aes aes;
		readonly ICryptoTransform cryptoTransform;

		public bool CanReuseTransform { get { return false; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return AesConstants.AES_BLOCK_SIZE; } }
		public int OutputBlockSize { get { return AesConstants.AES_BLOCK_SIZE; } }

		/// <summary>ctor</summary>
		public AesCtrCryptoTransform(byte[] key, ArraySegment<byte> counterBufferSegment, Func<Aes> aesFactory = null)
		{
			if (counterBufferSegment.Count != AesConstants.AES_BLOCK_SIZE)
				throw new ArgumentException("counterBufferSegment.Count must be " + AesConstants.STR_AES_BLOCK_SIZE + ".");

			this.aes = aesFactory == null ? AesFactories.Aes() : aesFactory();
			this.aes.Mode = CipherMode.ECB;
			this.aes.Padding = PaddingMode.None;

			Utils.BlockCopy(counterBufferSegment.Array, counterBufferSegment.Offset, _counterBuffer.Value, 0, AesConstants.AES_BLOCK_SIZE);
			this.cryptoTransform = aes.CreateEncryptor(rgbKey: key, rgbIV: null);
		}// ctor

		#region public
		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			int partialBlockSize = inputCount % AesConstants.AES_BLOCK_SIZE;
			int fullBlockSize = inputCount & (-AesConstants.AES_BLOCK_SIZE);//inputCount - partialBlockSize;
			int i, j;
			byte[] counterBuffer = _counterBuffer.Value; // looks dumb, but local-access is faster than field-access

			for (i = outputOffset, /* reusing inputCount as iMax */ inputCount = outputOffset + fullBlockSize; i < inputCount; i += AesConstants.AES_BLOCK_SIZE)
			{
				Utils.BlockCopy(counterBuffer, 0, outputBuffer, i, AesConstants.AES_BLOCK_SIZE);
				for (j = AesConstants.AES_BLOCK_SIZE - 1; j >= AesConstants.AES_BLOCK_SIZE - AesConstants.COUNTER_SIZE; --j)
					if (++counterBuffer[j] != 0) break;
			}

			if (fullBlockSize > 0)
			{
				fullBlockSize = this.cryptoTransform.TransformBlock(outputBuffer, outputOffset, fullBlockSize, outputBuffer, outputOffset);
				//for (i = 0; i < fullBlockSize; ++i) outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
				Utils.Xor(outputBuffer, outputOffset, inputBuffer, inputOffset, fullBlockSize);
			}

			if (partialBlockSize > 0)
			{
				outputOffset += fullBlockSize;
				inputOffset += fullBlockSize;
				this.cryptoTransform.TransformBlock(counterBuffer, 0, AesConstants.AES_BLOCK_SIZE, counterBuffer, 0);
				for (i = 0; i < partialBlockSize; ++i) outputBuffer[outputOffset + i] = (byte)(counterBuffer[i] ^ inputBuffer[inputOffset + i]);
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
					Array.Clear(_counterBuffer.Value, 0, AesConstants.AES_BLOCK_SIZE);
					this.aes = null;
				}
			}
		}// Dispose()
		#endregion
	}// class AesCtrCryptoTransform
}//ns