using System;
using System.Security.Cryptography;
using System.Numerics;

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

			this.counterStruct = new Utils.LongStruct
			{
				B8 = counterBufferSegmentArray[counterBufferSegmentOffset + 08],
				B7 = counterBufferSegmentArray[counterBufferSegmentOffset + 09],
				B6 = counterBufferSegmentArray[counterBufferSegmentOffset + 10],
				B5 = counterBufferSegmentArray[counterBufferSegmentOffset + 11],
				B4 = counterBufferSegmentArray[counterBufferSegmentOffset + 12],
				B3 = counterBufferSegmentArray[counterBufferSegmentOffset + 13],
				B2 = counterBufferSegmentArray[counterBufferSegmentOffset + 14],
				B1 = counterBufferSegmentArray[counterBufferSegmentOffset + 15]
			};

			this.cryptoTransform = aes.CreateEncryptor(rgbKey: key, rgbIV: null);
			this.aes = aes;
		}// ctor

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

			var _counterStruct = this.counterStruct;

			// process full blocks, if any
			if (fullBlockSize > 0)
			{
				byte counterBuffer_00 = counterBuffer_KeyStreamBuffer[00];
				byte counterBuffer_01 = counterBuffer_KeyStreamBuffer[01];
				byte counterBuffer_02 = counterBuffer_KeyStreamBuffer[02];
				byte counterBuffer_03 = counterBuffer_KeyStreamBuffer[03];
				byte counterBuffer_04 = counterBuffer_KeyStreamBuffer[04];
				byte counterBuffer_05 = counterBuffer_KeyStreamBuffer[05];
				byte counterBuffer_06 = counterBuffer_KeyStreamBuffer[06];
				byte counterBuffer_07 = counterBuffer_KeyStreamBuffer[07];

				unchecked
				{
					for (i = outputOffset, /* reusing j as iMax */ j = outputOffset + fullBlockSize; i < j; i += AesConstants.AES_BLOCK_SIZE)
					{
						outputBuffer[i + 00] = counterBuffer_00;
						outputBuffer[i + 01] = counterBuffer_01;
						outputBuffer[i + 02] = counterBuffer_02;
						outputBuffer[i + 03] = counterBuffer_03;
						outputBuffer[i + 04] = counterBuffer_04;
						outputBuffer[i + 05] = counterBuffer_05;
						outputBuffer[i + 06] = counterBuffer_06;
						outputBuffer[i + 07] = counterBuffer_07;

						outputBuffer[i + 08] = _counterStruct.B8;
						outputBuffer[i + 09] = _counterStruct.B7;
						outputBuffer[i + 10] = _counterStruct.B6;
						outputBuffer[i + 11] = _counterStruct.B5;
						outputBuffer[i + 12] = _counterStruct.B4;
						outputBuffer[i + 13] = _counterStruct.B3;
						outputBuffer[i + 14] = _counterStruct.B2;
						outputBuffer[i + 15] = _counterStruct.B1;

						{ ++_counterStruct.UlongValue; };
					}//for
				}
				fullBlockSize = this.cryptoTransform.TransformBlock(outputBuffer, outputOffset, fullBlockSize, outputBuffer, outputOffset);
				i = 0;

				const bool VECTORIZE = true;
				if (VECTORIZE)
				{   // vectorized xor
					int vectorLength = Vector<byte>.Count, vectorLimit = fullBlockSize - vectorLength;
					for (; i <= vectorLimit; i += vectorLength)
					{
						var destVector = new Vector<byte>(outputBuffer, outputOffset + i);
						var leftVector = new Vector<byte>(inputBuffer, inputOffset + i);
						(destVector ^ leftVector).CopyTo(outputBuffer, outputOffset + i);
					}
				}

				for (; i < fullBlockSize; ++i) outputBuffer[outputOffset + i] ^= inputBuffer[inputOffset + i];
			}// if fullBlockSize > 0

			// process the remaining partial block, if any
			if (partialBlockSize > 0)
			{
				inputOffset += fullBlockSize;
				outputOffset += fullBlockSize;

				counterBuffer_KeyStreamBuffer[08] = _counterStruct.B8;
				counterBuffer_KeyStreamBuffer[09] = _counterStruct.B7;
				counterBuffer_KeyStreamBuffer[10] = _counterStruct.B6;
				counterBuffer_KeyStreamBuffer[11] = _counterStruct.B5;
				counterBuffer_KeyStreamBuffer[12] = _counterStruct.B4;
				counterBuffer_KeyStreamBuffer[13] = _counterStruct.B3;
				counterBuffer_KeyStreamBuffer[14] = _counterStruct.B2;
				counterBuffer_KeyStreamBuffer[15] = _counterStruct.B1;

				{ ++_counterStruct.UlongValue; };

				this.cryptoTransform.TransformBlock(counterBuffer_KeyStreamBuffer, 0, AesConstants.AES_BLOCK_SIZE, counterBuffer_KeyStreamBuffer, AesConstants.AES_BLOCK_SIZE);

				for (i = 0; i < partialBlockSize; ++i) outputBuffer[outputOffset + i] = (byte)(counterBuffer_KeyStreamBuffer[AesConstants.AES_BLOCK_SIZE + i] ^ inputBuffer[inputOffset + i]);
				this.keyStreamBytesRemaining = AesConstants.AES_BLOCK_SIZE - partialBlockSize;
			}//if partialBlockSize > 0

			this.counterStruct = _counterStruct;
			return inputCount;
		}// TransformBlock()

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			byte[] outputBuffer = (inputCount == 0) ? _emptyByteArray : new byte[inputCount];
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
					unchecked { for (int i = AesConstants.AES_BLOCK_SIZE; i < AesConstants.AES_BLOCK_SIZE * 2; ++i) counterBuffer_KeyStreamBuffer[i] = 0; }
					this.aes = null;
				}
			}// if aes is not null
		}// Dispose()
		#endregion

		static readonly byte[] _emptyByteArray = Array.Empty<byte>();
	}// class AesCtrCryptoTransform
}//ns