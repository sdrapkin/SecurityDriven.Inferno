using System;

namespace SecurityDriven.Inferno.Extensions
{
	public static class SerializationExtensions
	{
		public static byte[] ToBytes(this string str)
		{
			var length = str.Length;
			byte[] bytes = new byte[length * 2];
			char c;
			for (int i = 0; i < length; ++i)
			{
				c = str[i];
				bytes[i * 2] = (byte)c;
				bytes[i * 2 + 1] = (byte)(c >> 8);
			}
			return bytes;
		}//ToBytes()

		public static string FromBytes(this byte[] bytes)
		{
			int byteCount = bytes.Length;
			if (byteCount % 2 != 0)
				throw new ArgumentException($"'{nameof(bytes)}' array must have even number of bytes", nameof(bytes));

			char[] chars = new char[byteCount / 2];
			for (int i = 0; i < chars.Length; ++i)
			{
				chars[i] = (char)(bytes[i * 2] | (bytes[i * 2 + 1] << 8));
			}
			return new String(chars);
		}//FromBytes()

		public static string FromBytes(this ArraySegment<byte> bytesSegment)
		{
			byte[] bytesArray = bytesSegment.Array;
			int bytesLength = bytesSegment.Count;
			int bytesOffset = bytesSegment.Offset;

			if (bytesLength % 2 != 0)
				throw new ArgumentException($"'{nameof(bytesSegment)}' must have even number of bytes", nameof(bytesSegment));

			char[] chars = new char[bytesLength / 2];
			for (int i = 0; i < chars.Length; ++i)
			{
				chars[i] = (char)(bytesArray[bytesOffset + i * 2] | (bytesArray[bytesOffset + i * 2 + 1] << 8));
			}
			return new String(chars);
		}//FromBytes()
	}//class SerializationExtensions
}//ns