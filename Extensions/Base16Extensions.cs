using System;

namespace SecurityDriven.Inferno.Extensions
{
	public static class Base16Extensions
	{
        /// <summary>
        /// Converts a byte array into equivalent Base16-encoded string.
        /// </summary>
		public static string ToBase16(this byte[] binary, Base16Config config = null)
		{
			if (config == null)
				config = Base16Config.HexUppercase;
			var base16table = config.Base16table;

			var chars = new char[binary.Length * 2];
			for (int i = 0, b; i < binary.Length; ++i)
			{
				b = binary[i];
				chars[i * 2] = base16table[b >> 4];
				chars[i * 2 + 1] = base16table[b & 0xF];
			}
			return new string(chars);
		}//ToBase16()

        /// <summary>
        /// Converts a byte array into equivalent Base16-encoded string.
        /// </summary>
		public static string ToBase16(this ArraySegment<byte> binarySegment, Base16Config config = null)
		{
			if (config == null)
				config = Base16Config.HexUppercase;
			var base16table = config.Base16table;

			byte[] binaryArray = binarySegment.Array;
			int binaryLength = binarySegment.Count;
			int binaryOffset = binarySegment.Offset;

			var chars = new char[binaryLength * 2];
			for (int i = 0, b; i < binaryLength; ++i)
			{
				b = binaryArray[binaryOffset + i];
				chars[i * 2] = base16table[b >> 4];
				chars[i * 2 + 1] = base16table[b & 0xF];
			}
			return new string(chars);
		}//ToBase16()

		/// <summary>
		/// Converts a Base16-encoded string into equivalent byte array. Does not validate Base16 encoding correctness.
		/// </summary>
		public static byte[] FromBase16(this string str16, Base16Config config = null)
		{
			if (config == null)
				config = Base16Config.HexUppercase;

			var reverseMap = config.ReverseMap;

			byte[] result = new byte[str16.Length / 2];
			for (int i = 0; i < result.Length; ++i)
			{
				result[i] = (byte)((reverseMap[str16[i * 2]] << 4) + reverseMap[str16[i * 2 + 1]]);
			}
			return result;
		}//FromBase16
	}//class Base16Extensions
}//ns