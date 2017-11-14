using System.Runtime.CompilerServices;

namespace SecurityDriven.Inferno.Extensions
{
	public static class ByteArrayExtensions
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static byte[] CloneBytes(this byte[] bytes)
		{
			var clone = new byte[bytes.Length];
			Utils.BlockCopy(bytes, 0, clone, 0, bytes.Length);
			return clone;
		}//CloneBytes()

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static byte[] CloneBytes(this byte[] bytes, int offset, int count)
		{
			var clone = new byte[count];
			Utils.BlockCopy(bytes, offset, clone, 0, count);
			return clone;
		}//CloneBytes()
	}//class ByteArrayExtensions
}//ns