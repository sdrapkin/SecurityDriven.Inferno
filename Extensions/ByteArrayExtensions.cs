using System.Runtime.CompilerServices;

namespace SecurityDriven.Inferno.Extensions
{
	public static class ByteArrayExtensions
	{
		internal const int SHORT_BYTECOPY_THRESHOLD = 32;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static byte[] CloneBytes(this byte[] bytes) => CloneBytes(bytes, 0, bytes.Length);

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static byte[] CloneBytes(this byte[] bytes, int offset, int count)
		{
			var clone = new byte[count];

			if (count <= SHORT_BYTECOPY_THRESHOLD)
				for (int i = 0; i < count; ++i) clone[i] = bytes[offset + i];
			else
				Utils.BlockCopy(bytes, offset, clone, 0, count);

			return clone;
		}//CloneBytes()

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ClearBytes(this byte[] bytes) => ClearBytes(bytes, 0, bytes.Length);

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ClearBytes(this byte[] bytes, int offset, int count)
		{
			System.Array.Clear(bytes, offset, count);
		}//ClearBytes()
	}//class ByteArrayExtensions
}//ns