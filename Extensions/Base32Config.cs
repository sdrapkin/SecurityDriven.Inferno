using System;

namespace SecurityDriven.Inferno.Extensions
{
	/// <remarks>Not a constant-time implementation (memory lookups).</remarks>
	public class Base32Config
	{
		const int BASE = 32;

		internal char[] Base32table;
		internal long[] ReverseMap;
		int? hashcode;

		public Base32Config(char[] alphabet = null)
		{
			if (alphabet == null)
			{
				this.Base32table = Default.Base32table;
				this.ReverseMap = Default.ReverseMap;
				return;
			}

			if (alphabet.Length != BASE)
				throw new ArgumentOutOfRangeException(nameof(alphabet), $"'{nameof(alphabet)}' array must have exactly {BASE.ToString()} characters.");

			this.Base32table = alphabet;

			char ch;
			this.ReverseMap = new long[byte.MaxValue];
			for (int i = 0; i < Base32table.Length; ++i)
			{
				ch = Base32table[i];
				this.ReverseMap[char.ToUpperInvariant(ch)] = i;
				this.ReverseMap[char.ToLowerInvariant(ch)] = i;
			}
		}//ctor

		public override int GetHashCode()
		{
			if (this.hashcode == null)
				this.hashcode = new string(this.Base32table).GetHashCode();
			return this.hashcode.GetValueOrDefault();
		}

		public override bool Equals(object obj)
		{
			if (obj is not Base32Config rhs)
				return false;

			if (this.GetHashCode() != rhs.GetHashCode())
				return false;

			for (int i = 0; i < BASE; ++i)
			{
				if (this.Base32table[i] != rhs.Base32table[i])
					return false;
			}
			return true;
		}

		public static readonly Base32Config Default = new Base32Config("123456789ABCDEFGHJKMNPQRSTUVWXYZ".ToCharArray());
		public static readonly Base32Config Rfc = new Base32Config("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray());
	}//class Base32Config
}//ns