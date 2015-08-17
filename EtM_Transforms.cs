﻿using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno
{
	using SecurityDriven.Inferno.Cipher;
	public static class EtM_Transform_Constants
	{
		const int LOH_THRESHOLD = 85000 - 1;
		public const int ETM_CTR_OVERHEAD = EtM_CTR.CONTEXT_TWEAK_LENGTH /* key_tweak */ + EtM_CTR.NONCE_LENGTH /* nonce_tweak */ + EtM_CTR.MAC_LENGTH /* mac */;
		public const int INPUT_BLOCK_SIZE = (LOH_THRESHOLD - ETM_CTR_OVERHEAD) / AesConstants.AES_BLOCK_SIZE * AesConstants.AES_BLOCK_SIZE; // largest pre-overhead size below LOH divisible by blocksize (to avoid wasting keystream)
		public const int OUTPUT_BLOCK_SIZE = INPUT_BLOCK_SIZE + ETM_CTR_OVERHEAD;
	}// class EtM_Transform_Constants

	public class EtM_EncryptTransform : ICryptoTransform
	{
		public bool CanReuseTransform { get { return false; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return EtM_Transform_Constants.INPUT_BLOCK_SIZE; } }
		public int OutputBlockSize { get { return EtM_Transform_Constants.OUTPUT_BLOCK_SIZE; } }

		byte[] key;
	    public uint CurrentChunkNumber { get; private set; }
	    ArraySegment<byte>? salt;

		public uint CurrentChunkNumber { get { return this.currentChunkNumber; } }

		/// <summary>ctor</summary>
		public EtM_EncryptTransform(byte[] key, ArraySegment<byte>? salt = null, uint chunkNumber = 1)
		{
			if (key == null) throw new ArgumentNullException("key", "key cannot be null.");
			this.key = key;
			this.salt = salt;
			this.CurrentChunkNumber = chunkNumber;
		}

		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			int partialBlockSize = inputCount % EtM_Transform_Constants.INPUT_BLOCK_SIZE;
			int fullBlockSize = inputCount - partialBlockSize;

			if (partialBlockSize != 0)
				throw new Exception("inputCount must be a multiple of input block size (" + EtM_Transform_Constants.INPUT_BLOCK_SIZE.ToString() + ").");

			int i = 0, j = 0;
			if (fullBlockSize > 0)
			{
				for (; i < fullBlockSize; i += EtM_Transform_Constants.INPUT_BLOCK_SIZE, j += EtM_Transform_Constants.OUTPUT_BLOCK_SIZE)
				{
					EtM_CTR.Encrypt(
						masterKey: this.key,
						plaintext: new ArraySegment<byte>(inputBuffer, inputOffset + i, EtM_Transform_Constants.INPUT_BLOCK_SIZE),
						output: outputBuffer,
						outputOffset: outputOffset + j,
						salt: this.salt,
						counter: this.CurrentChunkNumber++);
				}
			}
			return j;
		}// TransformBlock()

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (this.key == null) return null; // key would be null if this instance has already been disposed
			if (inputCount >= EtM_Transform_Constants.INPUT_BLOCK_SIZE)
				throw new Exception("Final input block size must be smaller than " + EtM_Transform_Constants.INPUT_BLOCK_SIZE.ToString() + ".");

			byte[] outputBuffer = new byte[EtM_Transform_Constants.ETM_CTR_OVERHEAD + inputCount];

			EtM_CTR.Encrypt(
				masterKey: this.key,
				plaintext: new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
				output: outputBuffer,
				outputOffset: 0,
				salt: this.salt,
				counter: this.CurrentChunkNumber);

			this.Dispose();
			return outputBuffer;
		}// TransformFinalBlock()

		public void Dispose()
		{
			this.key = null;
		}// Dispose()
	}// class EtM_EncryptTransform

	public class EtM_DecryptTransform : ICryptoTransform
	{
		public bool CanReuseTransform { get { return false; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return EtM_Transform_Constants.OUTPUT_BLOCK_SIZE; } }
		public int OutputBlockSize { get { return EtM_Transform_Constants.INPUT_BLOCK_SIZE; } }

		public bool IsComplete { get; private set; }
		public bool IsAuthenticateOnly { get; private set; }

		byte[] key;
		uint currentChunkNumber;
		ArraySegment<byte>? salt;

		public uint CurrentChunkNumber { get { return this.currentChunkNumber; } }

		/// <summary>ctor</summary>
		public EtM_DecryptTransform(byte[] key, ArraySegment<byte>? salt = null, uint chunkNumber = 1, bool authenticateOnly = false)
		{
			if (key == null) throw new ArgumentNullException("key", "key cannot be null.");
			this.key = key;
			this.salt = salt;
			this.currentChunkNumber = chunkNumber;
			this.IsAuthenticateOnly = authenticateOnly;
		}

		public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			int partialBlockSize = inputCount % EtM_Transform_Constants.OUTPUT_BLOCK_SIZE;
			int fullBlockSize = inputCount - partialBlockSize;

			if (partialBlockSize != 0)
				throw new Exception("inputCount must be a multiple of output block size (" + EtM_Transform_Constants.OUTPUT_BLOCK_SIZE.ToString() + ").");

			int i = 0, j = 0;
			if (fullBlockSize > 0)
			{
				var authenticateonly = this.IsAuthenticateOnly;
				for (; i < fullBlockSize; i += EtM_Transform_Constants.OUTPUT_BLOCK_SIZE, j += EtM_Transform_Constants.INPUT_BLOCK_SIZE)
				{
					var outputSegment = new ArraySegment<byte>?(new ArraySegment<byte>(outputBuffer, outputOffset + j, EtM_Transform_Constants.INPUT_BLOCK_SIZE));
					var cipherText = new ArraySegment<byte>(inputBuffer, inputOffset + i, EtM_Transform_Constants.OUTPUT_BLOCK_SIZE);

					if (authenticateonly)
					{
						if (!EtM_CTR.Authenticate(
							masterKey: this.key,
							ciphertext: cipherText,
							salt: this.salt,
							counter: this.currentChunkNumber))
							outputSegment = null;
					}
					else
					{
						EtM_CTR.Decrypt(
							masterKey: this.key,
							ciphertext: cipherText,
							outputSegment: ref outputSegment,
							salt: this.salt,
							counter: this.currentChunkNumber);
					}

					if (outputSegment == null)
					{
						this.key = null;
						throw new CryptographicException("Decryption failed for block " + this.currentChunkNumber.ToString() + ".");
					}
					++this.currentChunkNumber;
				}
			}
			return j;
		}// TransformBlock()

		public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (this.key == null) return null; // key would be null if this instance has already been disposed, or previously-called TransformBlock() failed
			if (inputCount >= EtM_Transform_Constants.OUTPUT_BLOCK_SIZE)
				throw new Exception("Final output block size must be smaller than " + EtM_Transform_Constants.OUTPUT_BLOCK_SIZE.ToString() + ".");

			if (inputCount < EtM_Transform_Constants.ETM_CTR_OVERHEAD)
				throw new Exception("Final output block size must must be at least " + EtM_Transform_Constants.ETM_CTR_OVERHEAD.ToString() + ".");

			byte[] outputBuffer = null;
			var cipherText = new ArraySegment<byte>(inputBuffer, inputOffset, inputCount);

			if (this.IsAuthenticateOnly)
			{
				if (EtM_CTR.Authenticate(
					masterKey: this.key,
					ciphertext: cipherText,
					salt: this.salt,
					counter: this.currentChunkNumber))
					outputBuffer = Utils.ZeroLengthArray<byte>.Value;
			}
			else
			{
				outputBuffer = EtM_CTR.Decrypt(
					masterKey: this.key,
					ciphertext: cipherText,
					salt: this.salt,
					counter: this.currentChunkNumber);
			}
			this.Dispose();
			if (outputBuffer == null)
				throw new CryptographicException("Decryption failed for block " + this.currentChunkNumber.ToString() + ".");

			this.IsComplete = true;
			return outputBuffer;
		}// TransformFinalBlock()

		public void Dispose()
		{
			this.key = null;
		}// Dispose()
	}// class EtM_DecryptTransform
}//ns