using System;

namespace SecurityDriven.Inferno.Extensions
{
	/// <remarks>Not a constant-time implementation (memory lookups).</remarks>
	public class Base16Config
	{
		const int BASE = 16;

		internal char[] Base16table;
		internal byte[] ReverseMap;
		int? hashcode;

		public Base16Config(char[] alphabet = null)
		{
			if (alphabet == null)
			{
				this.Base16table = HexUppercase.Base16table;
				this.ReverseMap = HexUppercase.ReverseMap;
				return;
			}

			if (alphabet.Length != BASE)
				throw new ArgumentOutOfRangeException("alphabet", "'alphabet' array must have exactly " + BASE + " characters.");

			this.Base16table = alphabet;

			char ch;
			this.ReverseMap = new byte[byte.MaxValue];
			for (byte i = 0; i < Base16table.Length; ++i)
			{
				ch = Base16table[i];
				this.ReverseMap[char.ToUpperInvariant(ch)] = i;
				this.ReverseMap[char.ToLowerInvariant(ch)] = i;
			}
		}//ctor

		public override int GetHashCode()
		{
			if (this.hashcode == null)
				this.hashcode = new string(this.Base16table).GetHashCode();
			return this.hashcode.Value;
		}

		public override bool Equals(object obj)
		{
			var rhs = obj as Base16Config;
			if (rhs == null)
				return false;

			if (this.GetHashCode() != rhs.GetHashCode())
				return false;

			for (int i = 0; i < BASE; ++i)
			{
				if (this.Base16table[i] != rhs.Base16table[i])
					return false;
			}
			return true;
		}

		public static readonly Base16Config HexUppercase = new Base16Config("0123456789ABCDEF".ToCharArray());
		public static readonly Base16Config HexLowercase = new Base16Config("0123456789abcdef".ToCharArray());
		public static readonly Base16Config HexYubiModhex = new Base16Config("cbdefghijklnrtuv".ToCharArray());
	}//class Base16Config
}//ns