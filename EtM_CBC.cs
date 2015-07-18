using System;
using System.Security.Cryptography;
using System.Threading;

namespace SecurityDriven.Inferno
{
	public static partial class EtM_CBC
	{
		static readonly Func<Aes> _aesFactory = Cipher.AesFactories.Aes;
		static readonly Func<Mac.HMAC2> _hmacFactory = Mac.HMACFactories.HMACSHA384;
		static readonly CryptoRandom _cryptoRandom = new CryptoRandom();

		const int AES_IV_LENGTH = Cipher.AesConstants.AES_BLOCK_SIZE;
		const int MAC_LENGTH = 16;
		const int MAC_KEY_LENGTH = MAC_LENGTH;
		const int ENC_KEY_LENGTH = 32;

		static readonly int HMAC_LENGTH = _hmacFactory().HashSize / 8;
		static readonly int CONTEXT_TWEAK_LENGTH = Math.Max(ENC_KEY_LENGTH - AES_IV_LENGTH, 0);
		static readonly int CONTEXT_BUFFER_LENGTH = CONTEXT_TWEAK_LENGTH + AES_IV_LENGTH;

		static readonly ThreadLocal<byte[]> _iv = new ThreadLocal<byte[]>(() => new byte[AES_IV_LENGTH]);
		static readonly ThreadLocal<byte[]> _contextBuffer = new ThreadLocal<byte[]>(() => new byte[CONTEXT_BUFFER_LENGTH]);
		static readonly ThreadLocal<byte[]> _encKey = new ThreadLocal<byte[]>(() => new byte[ENC_KEY_LENGTH]);
		static readonly ThreadLocal<byte[]> _macKey = new ThreadLocal<byte[]>(() => new byte[MAC_KEY_LENGTH]);
		static readonly ThreadLocal<byte[]> _sessionKey = new ThreadLocal<byte[]>(() => new byte[HMAC_LENGTH]);

		public static int CalculateCiphertextLength(ArraySegment<byte> plaintext)
		{
			int finalBlockLength = plaintext.Count - plaintext.Count / AES_IV_LENGTH * AES_IV_LENGTH; ;
			int paddingLength = AES_IV_LENGTH - finalBlockLength;
			return CONTEXT_BUFFER_LENGTH + plaintext.Count + paddingLength + MAC_LENGTH;
		}

		static void ValidateAes(Aes aes) // detect & fix any Mode/Padding deviation
		{
			if (aes.Mode == CipherMode.CBC && aes.Padding == PaddingMode.PKCS7) return;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.PKCS7;
		}

		static void ClearKeyMaterial()
		{
			Array.Clear(_encKey.Value, 0, ENC_KEY_LENGTH);
			Array.Clear(_macKey.Value, 0, MAC_KEY_LENGTH);
			Array.Clear(_sessionKey.Value, 0, HMAC_LENGTH);
		}

		public static void Encrypt(byte[] masterKey, ArraySegment<byte> plaintext, byte[] output, int outputOffset, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int fullBlockLength = plaintext.Count / AES_IV_LENGTH * AES_IV_LENGTH;
			int finalBlockLength = plaintext.Count - fullBlockLength;
			int paddingLength = AES_IV_LENGTH - finalBlockLength;
			int ciphertextLength = CONTEXT_BUFFER_LENGTH + plaintext.Count + paddingLength + MAC_LENGTH;
			if (output.Length - outputOffset < ciphertextLength) throw new ArgumentOutOfRangeException("output", "'output' array segment is not big enough for the ciphertext");

			try
			{
				using (var aes = _aesFactory())
				{
					EtM_CBC.ValidateAes(aes);
					_cryptoRandom.NextBytes(_contextBuffer.Value);

					Utils.BlockCopy(_contextBuffer.Value, CONTEXT_TWEAK_LENGTH, _iv.Value, 0, AES_IV_LENGTH);
					Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: _contextBuffer.Value.AsArraySegment(), derivedOutput: _sessionKey.Value.AsArraySegment(), counter: counter);

					Utils.BlockCopy(_sessionKey.Value, 0, _macKey.Value, 0, MAC_KEY_LENGTH);
					Utils.BlockCopy(_sessionKey.Value, MAC_KEY_LENGTH, _encKey.Value, 0, ENC_KEY_LENGTH);
					Utils.BlockCopy(_contextBuffer.Value, 0, output, outputOffset, CONTEXT_BUFFER_LENGTH);
					using (var aesEncryptor = aes.CreateEncryptor(_encKey.Value, _iv.Value))
					{
						if (fullBlockLength > 0)
							aesEncryptor.TransformBlock(inputBuffer: plaintext.Array, inputOffset: plaintext.Offset, inputCount: fullBlockLength, outputBuffer: output, outputOffset: outputOffset + CONTEXT_BUFFER_LENGTH);

						var finalBlockBuffer = aesEncryptor.TransformFinalBlock(inputBuffer: plaintext.Array, inputOffset: plaintext.Offset + fullBlockLength, inputCount: finalBlockLength);
						Utils.BlockCopy(finalBlockBuffer, 0, output, outputOffset + CONTEXT_BUFFER_LENGTH + fullBlockLength, finalBlockBuffer.Length);
					}// using aesEncryptor
				}// using aes

				using (var hmac = _hmacFactory())
				{
					hmac.Key = _macKey.Value;
					hmac.HashCore(output, outputOffset + CONTEXT_TWEAK_LENGTH, AES_IV_LENGTH + plaintext.Count + paddingLength);
					var fullmac = hmac.HashFinal();
					Utils.BlockCopy(fullmac, 0, output, outputOffset + ciphertextLength - MAC_LENGTH, MAC_LENGTH);
				}// using hmac
			}
			finally { EtM_CBC.ClearKeyMaterial(); }
		}// Encrypt()

		public static byte[] Encrypt(byte[] masterKey, ArraySegment<byte> plaintext, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int fullBlockLength = plaintext.Count / AES_IV_LENGTH * AES_IV_LENGTH;
			int finalBlockLength = plaintext.Count - fullBlockLength;
			int paddingLength = AES_IV_LENGTH - finalBlockLength;

			int ciphertextLength = CONTEXT_BUFFER_LENGTH + plaintext.Count + paddingLength + MAC_LENGTH;
			byte[] buffer = new byte[ciphertextLength];
			EtM_CBC.Encrypt(masterKey: masterKey, plaintext: plaintext, output: buffer, outputOffset: 0, salt: salt, counter: counter);
			return buffer;
		}// Encrypt()


		public static void Decrypt(byte[] masterKey, ArraySegment<byte> ciphertext, ref ArraySegment<byte>? outputSegment, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int cipherLength = ciphertext.Count - CONTEXT_BUFFER_LENGTH - MAC_LENGTH;
			if (cipherLength < AES_IV_LENGTH) { outputSegment = null; return; }
			int fullBlockLength = cipherLength - AES_IV_LENGTH;
			byte[] finalBlock = null;
			try
			{
				Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: new ArraySegment<byte>(ciphertext.Array, ciphertext.Offset, CONTEXT_BUFFER_LENGTH), derivedOutput: _sessionKey.Value.AsArraySegment(), counter: counter);
				Utils.BlockCopy(_sessionKey.Value, 0, _macKey.Value, 0, MAC_KEY_LENGTH);

				using (var hmac = _hmacFactory())
				{
					hmac.Key = _macKey.Value;
					hmac.HashCore(ciphertext.Array, ciphertext.Offset + CONTEXT_TWEAK_LENGTH, AES_IV_LENGTH + cipherLength);
					var fullmacActual = hmac.HashFinal();
					if (!Utils.ConstantTimeEqual(fullmacActual, 0, ciphertext.Array, ciphertext.Offset + ciphertext.Count - MAC_LENGTH, MAC_LENGTH)) { outputSegment = null; return; };
				}// using hmac

				Utils.BlockCopy(ciphertext.Array, ciphertext.Offset + CONTEXT_TWEAK_LENGTH, _iv.Value, 0, AES_IV_LENGTH);
				Utils.BlockCopy(_sessionKey.Value, MAC_KEY_LENGTH, _encKey.Value, 0, ENC_KEY_LENGTH);

				using (var aes = _aesFactory())
				{
					EtM_CBC.ValidateAes(aes);
					using (var aesDecryptor = aes.CreateDecryptor(_encKey.Value, _iv.Value))
					{
						int fullBlockTransformed = 0;
						if (fullBlockLength > 0)
							fullBlockTransformed = aesDecryptor.TransformBlock(inputBuffer: ciphertext.Array, inputOffset: ciphertext.Offset + CONTEXT_BUFFER_LENGTH, inputCount: fullBlockLength, outputBuffer: outputSegment.Value.Array, outputOffset: outputSegment.Value.Offset);

						finalBlock = aesDecryptor.TransformFinalBlock(ciphertext.Array, ciphertext.Offset + CONTEXT_BUFFER_LENGTH + fullBlockLength, cipherLength - fullBlockLength);
						Utils.BlockCopy(finalBlock, 0, outputSegment.Value.Array, outputSegment.Value.Offset + fullBlockTransformed, finalBlock.Length);
						outputSegment = new ArraySegment<byte>?(new ArraySegment<byte>(outputSegment.Value.Array, outputSegment.Value.Offset, fullBlockTransformed + finalBlock.Length));
					}// using aesDecryptor
				}// using aes
			}
			finally
			{
				EtM_CBC.ClearKeyMaterial();
				if (finalBlock != null) Array.Clear(finalBlock, 0, finalBlock.Length);
			}
		}// Decrypt()

		public static byte[] Decrypt(byte[] masterKey, ArraySegment<byte> ciphertext, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int cipherLength = ciphertext.Count - CONTEXT_BUFFER_LENGTH - MAC_LENGTH;
			if (cipherLength < AES_IV_LENGTH) return null;
			try
			{
				Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: new ArraySegment<byte>(ciphertext.Array, ciphertext.Offset, CONTEXT_BUFFER_LENGTH), derivedOutput: _sessionKey.Value.AsArraySegment(), counter: counter);
				Utils.BlockCopy(_sessionKey.Value, 0, _macKey.Value, 0, MAC_KEY_LENGTH);

				using (var hmac = _hmacFactory())
				{
					hmac.Key = _macKey.Value;
					hmac.HashCore(ciphertext.Array, ciphertext.Offset + CONTEXT_TWEAK_LENGTH, AES_IV_LENGTH + cipherLength);
					var fullmacActual = hmac.HashFinal();
					if (!Utils.ConstantTimeEqual(fullmacActual, 0, ciphertext.Array, ciphertext.Offset + ciphertext.Count - MAC_LENGTH, MAC_LENGTH)) return null;
				}// using hmac

				Utils.BlockCopy(ciphertext.Array, ciphertext.Offset + CONTEXT_TWEAK_LENGTH, _iv.Value, 0, AES_IV_LENGTH);
				Utils.BlockCopy(_sessionKey.Value, MAC_KEY_LENGTH, _encKey.Value, 0, ENC_KEY_LENGTH);

				using (var aes = _aesFactory())
				{
					EtM_CBC.ValidateAes(aes);
					using (var aesDecryptor = aes.CreateDecryptor(_encKey.Value, _iv.Value))
					{
						return aesDecryptor.TransformFinalBlock(ciphertext.Array, ciphertext.Offset + CONTEXT_BUFFER_LENGTH, cipherLength);
					}// using aesDecryptor
				}// using aes
			}
			finally { EtM_CBC.ClearKeyMaterial(); }
		}// Decrypt()

		public static bool Authenticate(byte[] masterKey, ArraySegment<byte> ciphertext, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int cipherLength = ciphertext.Count - CONTEXT_BUFFER_LENGTH - MAC_LENGTH;
			if (cipherLength < AES_IV_LENGTH) return false;
			try
			{
				Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: new ArraySegment<byte>(ciphertext.Array, ciphertext.Offset, CONTEXT_BUFFER_LENGTH), derivedOutput: _sessionKey.Value.AsArraySegment(), counter: counter);
				Utils.BlockCopy(_sessionKey.Value, 0, _macKey.Value, 0, MAC_KEY_LENGTH);
				using (var hmac = _hmacFactory())
				{
					hmac.Key = _macKey.Value;
					hmac.HashCore(ciphertext.Array, ciphertext.Offset + CONTEXT_TWEAK_LENGTH, AES_IV_LENGTH + cipherLength);
					var fullmacActual = hmac.HashFinal();
					if (!Utils.ConstantTimeEqual(fullmacActual, 0, ciphertext.Array, ciphertext.Offset + ciphertext.Count - MAC_LENGTH, MAC_LENGTH)) return false;
				}// using hmac
				return true;
			}
			finally { EtM_CBC.ClearKeyMaterial(); }
		}// Authenticate()
	}//class EtM_CBC
}//ns