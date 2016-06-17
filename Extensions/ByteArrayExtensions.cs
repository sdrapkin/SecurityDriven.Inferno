namespace SecurityDriven.Inferno.Extensions
{
	internal static class ByteArrayExtensions
	{
		internal static byte[] CloneBytes(this byte[] bytes)
		{
			var clone = new byte[bytes.Length];
			Utils.BlockCopy(bytes, 0, clone, 0, bytes.Length);
			return clone;
		}//Clone()

		internal static byte[] CloneBytes(this byte[] bytes, int offset, int count)
		{
			var clone = new byte[count];
			Utils.BlockCopy(bytes, offset, clone, 0, count);
			return clone;
		}//Clone()
	}//class ByteArrayExtensions
}//ns