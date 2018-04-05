using System;
using System.Security.Cryptography;

namespace SecurityDriven.Inferno.Kdf
{
	using Mac;

	/// <remarks>
	/// Concepts from:
	/// http://dx.doi.org/10.6028/NIST.SP.800-108
	/// http://referencesource.microsoft.com/#System.Web/Security/Cryptography/SP800_108.cs
	/// </remarks>
	public static class SP800_108_Ctr
	{
		const int COUNTER_LENGTH = sizeof(uint), DERIVED_KEY_LENGTH_LENGTH = sizeof(uint);

		internal static byte[] CreateBuffer(ArraySegment<byte>? label, ArraySegment<byte>? context, uint keyLengthInBits)
		{
			int labelLength = (label != null) ? label.GetValueOrDefault().Count : 0;
			int contextLength = (context != null) ? context.GetValueOrDefault().Count : 0;
			int bufferLength = (COUNTER_LENGTH /* counter */) + (labelLength + 1 /* label + 0x00 */) + (contextLength /* context */) + (DERIVED_KEY_LENGTH_LENGTH /* [L]_2 */);
			var buffer = new byte[bufferLength];

			// store label, if any
			if (labelLength > 0)
			{
				var labelSegment = label.GetValueOrDefault();
				var labelSegmentArray = labelSegment.Array;
				var labelSegmentOffset = labelSegment.Offset;

				if (labelLength > Extensions.ByteArrayExtensions.SHORT_BYTECOPY_THRESHOLD)
					Utils.BlockCopy(labelSegmentArray, labelSegmentOffset, buffer, COUNTER_LENGTH, labelLength);
				else
					for (int i = 0; i < labelLength; ++i) buffer[COUNTER_LENGTH + i] = labelSegmentArray[labelSegmentOffset + i];
			}

			// store context, if any
			if (contextLength > 0)
			{
				var contextSegment = context.GetValueOrDefault();
				var contextSegmentArray = contextSegment.Array;
				var contextSegmentOffset = contextSegment.Offset;

				if (contextLength > Extensions.ByteArrayExtensions.SHORT_BYTECOPY_THRESHOLD)
					Utils.BlockCopy(contextSegment.Array, contextSegment.Offset, buffer, COUNTER_LENGTH + labelLength + 1, contextLength);
				else
					for (int i = 0; i < contextLength; ++i) buffer[COUNTER_LENGTH + labelLength + 1 + i] = contextSegmentArray[contextSegmentOffset + i];
			}

			// store key length
			new Utils.IntStruct { UintValue = keyLengthInBits }.ToBEBytes(buffer, bufferLength - DERIVED_KEY_LENGTH_LENGTH);
			return buffer;
		}// CreateBuffer()

		public static void DeriveKey(Func<HMAC> hmacFactory, byte[] key, ArraySegment<byte>? label, ArraySegment<byte>? context, ArraySegment<byte> derivedOutput, uint counter = 1)
		{
			using (var hmac = hmacFactory())
			{
				hmac.Key = key;
				var buffer = CreateBuffer(label: label, context: context, keyLengthInBits: checked((uint)(derivedOutput.Count << 3)));
				DeriveKey(hmac, buffer.AsArraySegment(), derivedOutput, counter);
			}
		}// DeriveKey()

		internal static void DeriveKey(HMAC keyedHmac, ArraySegment<byte> bufferSegment, ArraySegment<byte> derivedOutput, uint counter = 1)
		{
			int derivedOutputCount = derivedOutput.Count, derivedOutputOffset = derivedOutput.Offset;
			var derivedOutputArray = derivedOutput.Array;
			byte[] K_i = null;
			HMAC2 keyedHmac2 = keyedHmac as HMAC2;
			checked
			{
				// Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.
				for (var counterStruct = new Utils.IntStruct { UintValue = counter }; derivedOutputCount > 0; ++counterStruct.UintValue)
				{
					counterStruct.ToBEBytes(bufferSegment.Array, bufferSegment.Offset); // update the counter within the buffer

					if (keyedHmac2 == null)
					{
						K_i = keyedHmac.ComputeHash(bufferSegment.Array, bufferSegment.Offset, bufferSegment.Count);
					}
					else
					{
						keyedHmac2.TransformBlock(bufferSegment.Array, bufferSegment.Offset, bufferSegment.Count, null, 0);
						keyedHmac2.TransformFinalBlock(bufferSegment.Array, 0, 0);
						K_i = keyedHmac2.HashInner;
					}

					// copy the leftmost bits of K_i into the output buffer
					int numBytesToCopy = derivedOutputCount > K_i.Length ? K_i.Length : derivedOutputCount;//Math.Min(derivedOutputCount, K_i.Length);

					//Utils.BlockCopy(K_i, 0, derivedOutput.Array, derivedOutputOffset, numBytesToCopy);
					for (int i = 0; i < numBytesToCopy; ++i) derivedOutputArray[derivedOutputOffset + i] = K_i[i];

					derivedOutputOffset += numBytesToCopy;
					derivedOutputCount -= numBytesToCopy;
				}// for
			}// checked
			if (keyedHmac2 == null && K_i != null) Array.Clear(K_i, 0, K_i.Length); /* clean up needed only when HMAC implementation is not HMAC2 */
		}// DeriveKey()
	}// class SP800_108
}//ns