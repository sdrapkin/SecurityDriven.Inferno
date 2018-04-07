using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;

namespace SecurityDriven.Inferno
{
	public static partial class EtM_CTR
	{
		static readonly Func<Aes> _aesFactory = Cipher.AesFactories.Aes;
		static readonly Func<Mac.HMAC2> _hmacFactory = Mac.HMACFactories.HMACSHA384;
		static readonly CryptoRandom _cryptoRandom = new CryptoRandom();

		internal const int MAC_LENGTH = 128 / 8;
		const int MAC_KEY_LENGTH = MAC_LENGTH;
		const int ENC_KEY_LENGTH = 256 / 8;

		static readonly int HMAC_LENGTH = _hmacFactory().HashSize / 8;
		internal const int CONTEXT_TWEAK_LENGTH = ENC_KEY_LENGTH;
		internal const int NONCE_LENGTH = Cipher.AesConstants.AES_BLOCK_SIZE / 2;
		const int CONTEXT_BUFFER_LENGTH = CONTEXT_TWEAK_LENGTH + NONCE_LENGTH;

		/*
		static readonly ThreadLocal<byte[]> _counterBuffer = new ThreadLocal<byte[]>(() => new byte[Cipher.AesConstants.AES_BLOCK_SIZE]);
		static readonly ThreadLocal<byte[]> _contextBuffer = new ThreadLocal<byte[]>(() => new byte[CONTEXT_BUFFER_LENGTH]);
		static readonly ThreadLocal<byte[]> _encKey = new ThreadLocal<byte[]>(() => new byte[ENC_KEY_LENGTH]);
		static readonly ThreadLocal<byte[]> _macKey = new ThreadLocal<byte[]>(() => new byte[MAC_KEY_LENGTH]);
		static readonly ThreadLocal<byte[]> _sessionKey = new ThreadLocal<byte[]>(() => new byte[HMAC_LENGTH]);
		*/

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ClearKeyMaterial(byte[] encKey, byte[] macKey, byte[] sessionKey)
		{
			Array.Clear(encKey, 0, encKey.Length);
			Array.Clear(macKey, 0, macKey.Length);
			Array.Clear(sessionKey, 0, sessionKey.Length);
		}// ClearKeyMaterial()

		public static void Encrypt(byte[] masterKey, ArraySegment<byte> plaintext, byte[] output, int outputOffset, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int ciphertextLength = CONTEXT_BUFFER_LENGTH + plaintext.Count + MAC_LENGTH;
			if (output.Length - outputOffset < ciphertextLength) throw new ArgumentOutOfRangeException(nameof(output), $"'{nameof(output)}' array segment is not big enough for the ciphertext");

			var counterBuffer = new byte[Cipher.AesConstants.AES_BLOCK_SIZE];
			var contextBuffer = new byte[CONTEXT_BUFFER_LENGTH];
			var encKey = new byte[ENC_KEY_LENGTH];
			var macKey = new byte[MAC_KEY_LENGTH];
			var sessionKey = new byte[HMAC_LENGTH];

			try
			{
				_cryptoRandom.NextBytes(contextBuffer, 0, CONTEXT_BUFFER_LENGTH);

				Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: new ArraySegment<byte>(contextBuffer, 0, CONTEXT_TWEAK_LENGTH), derivedOutput: sessionKey.AsArraySegment(), counter: counter);

				//Utils.BlockCopy(sessionKey, 0, macKey, 0, MAC_KEY_LENGTH);
				for (int i = 0; i < macKey.Length; ++i) macKey[i] = sessionKey[i];

				//Utils.BlockCopy(sessionKey, MAC_KEY_LENGTH, encKey, 0, ENC_KEY_LENGTH);
				for (int i = 0; i < encKey.Length; ++i) encKey[i] = sessionKey[MAC_KEY_LENGTH + i];

				//Utils.BlockCopy(contextBuffer, 0, output, outputOffset, CONTEXT_BUFFER_LENGTH);
				for (int i = 0; i < contextBuffer.Length; ++i) output[outputOffset + i] = contextBuffer[i];

				//Utils.BlockCopy(contextBuffer, CONTEXT_TWEAK_LENGTH, counterBuffer, 0, NONCE_LENGTH);
				for (int i = 0; i < NONCE_LENGTH; ++i) counterBuffer[i] = contextBuffer[CONTEXT_TWEAK_LENGTH + i];

				using (var ctrTransform = new Cipher.AesCtrCryptoTransform(key: encKey, counterBufferSegment: counterBuffer.AsArraySegment(), aesFactory: _aesFactory))
				{
					ctrTransform.TransformBlock(inputBuffer: plaintext.Array, inputOffset: plaintext.Offset, inputCount: plaintext.Count, outputBuffer: output, outputOffset: outputOffset + CONTEXT_BUFFER_LENGTH);
				}// using aesEncryptor

				using (var hmac = _hmacFactory())
				{
					hmac.Key = macKey;
					hmac.TransformBlock(output, outputOffset + CONTEXT_TWEAK_LENGTH, NONCE_LENGTH + plaintext.Count, null, 0);
					hmac.TransformFinalBlock(output, 0, 0);
					var fullmac = hmac.HashInner;

					//Utils.BlockCopy(fullmac, 0, output, outputOffset + ciphertextLength - MAC_LENGTH, MAC_LENGTH);
					for (int i = 0; i < MAC_LENGTH; ++i) output[outputOffset + ciphertextLength - MAC_LENGTH + i] = fullmac[i];
				}// using hmac
			}
			finally { EtM_CTR.ClearKeyMaterial(encKey, macKey, sessionKey); }
		}// Encrypt()

		public static byte[] Encrypt(byte[] masterKey, ArraySegment<byte> plaintext, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			byte[] buffer = new byte[CONTEXT_BUFFER_LENGTH + plaintext.Count + MAC_LENGTH];
			EtM_CTR.Encrypt(masterKey: masterKey, plaintext: plaintext, output: buffer, outputOffset: 0, salt: salt, counter: counter);
			return buffer;
		}// Encrypt()

		public static void Decrypt(byte[] masterKey, ArraySegment<byte> ciphertext, ref ArraySegment<byte>? outputSegment, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int cipherLength = ciphertext.Count - CONTEXT_BUFFER_LENGTH - MAC_LENGTH;
			if (cipherLength < 0) { outputSegment = null; return; }

			var counterBuffer = new byte[Cipher.AesConstants.AES_BLOCK_SIZE];
			var encKey = new byte[ENC_KEY_LENGTH];
			var macKey = new byte[MAC_KEY_LENGTH];
			var sessionKey = new byte[HMAC_LENGTH];

			try
			{
				var ciphertextArray = ciphertext.Array;
				var ciphertextOffset = ciphertext.Offset;

				Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: new ArraySegment<byte>(ciphertextArray, ciphertextOffset, CONTEXT_TWEAK_LENGTH), derivedOutput: sessionKey.AsArraySegment(), counter: counter);

				//Utils.BlockCopy(sessionKey, 0, macKey, 0, MAC_KEY_LENGTH);
				for (int i = 0; i < macKey.Length; ++i) macKey[i] = sessionKey[i];

				using (var hmac = _hmacFactory())
				{
					hmac.Key = macKey;
					hmac.TransformBlock(ciphertextArray, ciphertextOffset + CONTEXT_TWEAK_LENGTH, NONCE_LENGTH + cipherLength, null, 0);
					hmac.TransformFinalBlock(ciphertextArray, 0, 0);
					var fullmacActual = hmac.HashInner;
					if (!Utils.ConstantTimeEqual(fullmacActual, 0, ciphertextArray, ciphertextOffset + ciphertext.Count - MAC_LENGTH, MAC_LENGTH)) { outputSegment = null; return; };
				}// using hmac

				if (outputSegment == null) outputSegment = (new byte[cipherLength]).AsNullableArraySegment();

				//Utils.BlockCopy(ciphertext.Array, ciphertext.Offset + CONTEXT_TWEAK_LENGTH, counterBuffer, 0, NONCE_LENGTH);
				for (int i = 0; i < NONCE_LENGTH; ++i) counterBuffer[i] = ciphertextArray[ciphertextOffset + CONTEXT_TWEAK_LENGTH + i];

				//Utils.BlockCopy(sessionKey, MAC_KEY_LENGTH, encKey, 0, ENC_KEY_LENGTH);
				for (int i = 0; i < encKey.Length; ++i) encKey[i] = sessionKey[MAC_KEY_LENGTH + i];

				using (var ctrTransform = new Cipher.AesCtrCryptoTransform(key: encKey, counterBufferSegment: counterBuffer.AsArraySegment(), aesFactory: _aesFactory))
				{
					ctrTransform.TransformBlock(inputBuffer: ciphertextArray, inputOffset: ciphertextOffset + CONTEXT_BUFFER_LENGTH, inputCount: cipherLength, outputBuffer: outputSegment.GetValueOrDefault().Array, outputOffset: outputSegment.GetValueOrDefault().Offset);
				}// using aesDecryptor
			}
			finally { EtM_CTR.ClearKeyMaterial(encKey, macKey, sessionKey); }
		}// Decrypt()

		public static byte[] Decrypt(byte[] masterKey, ArraySegment<byte> ciphertext, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int cipherLength = ciphertext.Count - CONTEXT_BUFFER_LENGTH - MAC_LENGTH;
			if (cipherLength < 0) return null;
			var bufferSegment = default(ArraySegment<byte>?);
			EtM_CTR.Decrypt(masterKey, ciphertext, ref bufferSegment, salt, counter);
			return (bufferSegment != null) ? bufferSegment.GetValueOrDefault().Array : null;
		}// Decrypt()

		public static bool Authenticate(byte[] masterKey, ArraySegment<byte> ciphertext, ArraySegment<byte>? salt = null, uint counter = 1)
		{
			int cipherLength = ciphertext.Count - CONTEXT_BUFFER_LENGTH - MAC_LENGTH;
			if (cipherLength < 0) return false;

			var encKey = new byte[ENC_KEY_LENGTH];
			var macKey = new byte[MAC_KEY_LENGTH];
			var sessionKey = new byte[HMAC_LENGTH];

			try
			{
				var ciphertextArray = ciphertext.Array;
				var ciphertextOffset = ciphertext.Offset;

				Kdf.SP800_108_Ctr.DeriveKey(hmacFactory: _hmacFactory, key: masterKey, label: salt, context: new ArraySegment<byte>(ciphertextArray, ciphertextOffset, CONTEXT_TWEAK_LENGTH), derivedOutput: sessionKey.AsArraySegment(), counter: counter);

				//Utils.BlockCopy(sessionKey, 0, macKey, 0, MAC_KEY_LENGTH);
				for (int i = 0; i < macKey.Length; ++i) macKey[i] = sessionKey[i];

				using (var hmac = _hmacFactory())
				{
					hmac.Key = macKey;
					hmac.TransformBlock(ciphertextArray, ciphertextOffset + CONTEXT_TWEAK_LENGTH, NONCE_LENGTH + cipherLength, null, 0);
					hmac.TransformFinalBlock(ciphertextArray, 0, 0);
					var fullmacActual = hmac.HashInner;
					if (!Utils.ConstantTimeEqual(fullmacActual, 0, ciphertextArray, ciphertextOffset + ciphertext.Count - MAC_LENGTH, MAC_LENGTH)) return false;
				}// using hmac
				return true;
			}
			finally { EtM_CTR.ClearKeyMaterial(encKey, macKey, sessionKey); }
		}// Authenticate()
	}//class EtM_CTR
}//ns