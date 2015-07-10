using System;

namespace SecurityDriven.Inferno.Extensions
{
	public static class Base32Extensions
	{
		public static string ToBase32(this byte[] binary, Base32Config config = null)
		{
			int length = binary.Length;
			int bitLength = length * 8;
			int base32Length = bitLength / 5;
			if (base32Length * 5 != bitLength)
				throw new ArgumentOutOfRangeException("binary", "'binary' array length must be a multiple of 5.");

			if (config == null)
				config = Base32Config.Default;
			var base32table = config.Base32table;

			char[] chArray = new char[base32Length];
			for (int i = 0, num2Start = 7, num2 = num2Start, index, num4; i < length; i += 5, num2Start += 8, num2 = num2Start)
			{
				num4 = binary[i + 1] << 24 | binary[i + 2] << 16 | binary[i + 3] << 8 | binary[i + 4];

				index = num4 & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 5) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 10) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 15) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 20) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 25) & 31;
				chArray[num2--] = base32table[index];

				num4 = (num4 >> 30) & 3 | binary[i] << 2;
				index = num4 & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 5) & 31;
				chArray[num2--] = base32table[index];
			}
			return new string(chArray);
		}//ToBase32()

		public static string ToBase32(this ArraySegment<byte> binarySegment, Base32Config config = null)
		{
			byte[] binaryArray = binarySegment.Array;
			int binaryLength = binarySegment.Count;
			int binaryOffset = binarySegment.Offset;

			int bitLength = binaryLength * 8;
			int base32Length = bitLength / 5;
			if (base32Length * 5 != bitLength)
				throw new ArgumentOutOfRangeException("binary", "'binary' array length must be a multiple of 5.");

			if (config == null)
				config = Base32Config.Default;
			var base32table = config.Base32table;

			char[] chArray = new char[base32Length];
			for (int i = 0, num2Start = 7, num2 = num2Start, index, num4; i < binaryLength; i += 5, num2Start += 8, num2 = num2Start)
			{
				num4 = binaryArray[binaryOffset + i + 1] << 24 | binaryArray[binaryOffset + i + 2] << 16 | binaryArray[binaryOffset + i + 3] << 8 | binaryArray[binaryOffset + i + 4];

				index = num4 & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 5) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 10) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 15) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 20) & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 25) & 31;
				chArray[num2--] = base32table[index];

				num4 = (num4 >> 30) & 3 | binaryArray[binaryOffset + i] << 2;
				index = num4 & 31;
				chArray[num2--] = base32table[index];

				index = (num4 >> 5) & 31;
				chArray[num2--] = base32table[index];
			}
			return new string(chArray);
		}//ToBase32()

		public static byte[] FromBase32(this string str32, Base32Config config = null)
		{
			int length = str32.Length;
			int bit5length = length / 8;
			if (bit5length * 8 != length)
				throw new ArgumentOutOfRangeException("str32", "'str32' string length must be a multiple of 8.");

			if (config == null)
				config = Base32Config.Default;
			var reverseMap = config.ReverseMap;

			int byteLength = bit5length * 5;
			byte[] result = new byte[byteLength];

			long tmp;
			for (int i = 0, indexStart = 4, index = indexStart; i < length; i += 8, indexStart += 5, index = indexStart)
			{
				tmp =
					reverseMap[str32[i + 0]] << 35 |
					reverseMap[str32[i + 1]] << 30 |
					reverseMap[str32[i + 2]] << 25 |
					reverseMap[str32[i + 3]] << 20 |
					reverseMap[str32[i + 4]] << 15 |
					reverseMap[str32[i + 5]] << 10 |
					reverseMap[str32[i + 6]] << 5 |
					reverseMap[str32[i + 7]];

				result[index--] = (byte)tmp; tmp >>= 8;
				result[index--] = (byte)tmp; tmp >>= 8;
				result[index--] = (byte)tmp; tmp >>= 8;
				result[index--] = (byte)tmp; tmp >>= 8;
				result[index--] = (byte)tmp; tmp >>= 8;
			}
			return result;
		}//FromBase32()
	}//class Base32Extensions
}//ns