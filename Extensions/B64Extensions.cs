using System;

namespace SecurityDriven.Inferno.Extensions
{
	/*
	 * This implementation of URL-safe Base64 encode/decode is borrowed from
	 * http://referencesource.microsoft.com/#System.Web/Util/HttpEncoder.cs
	 * 
	 * The reason for reproducing this logic is to avoid dependency on System.Web.dll
	*/
	public static class B64Extensions
	{
		public static string ToB64(this byte[] input)
		{
			return input.AsArraySegment().ToB64();
		}

		// UrlTokenEncode() equivalent
		public static string ToB64(this ArraySegment<byte> inputSegment)
		{
			byte[] inputArray = inputSegment.Array;
			int inputLength = inputSegment.Count;

			if (inputLength < 1)
				return String.Empty;

			int inputOffset = inputSegment.Offset;
			string base64Str = null;
			int endPos = 0;
			char[] base64Chars = null;

			////////////////////////////////////////////////////////
			// Step 1: Do a Base64 encoding
			base64Str = Convert.ToBase64String(inputArray, inputOffset, inputLength);
			if (base64Str == null)
				return null;

			////////////////////////////////////////////////////////
			// Step 2: Find how many padding chars are present in the end
			for (endPos = base64Str.Length; endPos > 0; endPos--)
			{
				if (base64Str[endPos - 1] != '=') // Found a non-padding char!
				{
					break; // Stop here
				}
			}

			////////////////////////////////////////////////////////
			// Step 3: Create char array to store all non-padding chars,
			//      plus a char to indicate how many padding chars are needed
			base64Chars = new char[endPos + 1];
			base64Chars[endPos] = (char)((int)'0' + base64Str.Length - endPos); // Store a char at the end, to indicate how many padding chars are needed

			////////////////////////////////////////////////////////
			// Step 3: Copy in the other chars. Transform the "+" to "-", and "/" to "_"
			for (int iter = 0; iter < endPos; iter++)
			{
				char c = base64Str[iter];

				switch (c)
				{
					case '+':
						base64Chars[iter] = '-';
						break;

					case '/':
						base64Chars[iter] = '_';
						break;

					case '=':
						System.Diagnostics.Debug.Assert(false);
						base64Chars[iter] = c;
						break;

					default:
						base64Chars[iter] = c;
						break;
				}
			}
			return new string(base64Chars);
		}// ToB64()

		// UrlTokenDecode() equivalent
		public static byte[] FromB64(this string input)
		{
			if (input == null)
				throw new ArgumentNullException(nameof(input));

			int len = input.Length;
			if (len < 1)
				return Utils.ZeroLengthArray<byte>.Value;

			///////////////////////////////////////////////////////////////////
			// Step 1: Calculate the number of padding chars to append to this string.
			//         The number of padding chars to append is stored in the last char of the string.
			int numPadChars = (int)input[len - 1] - (int)'0';
			if (numPadChars < 0 || numPadChars > 10)
				return null;

			///////////////////////////////////////////////////////////////////
			// Step 2: Create array to store the chars (not including the last char)
			//          and the padding chars
			char[] base64Chars = new char[len - 1 + numPadChars];


			////////////////////////////////////////////////////////
			// Step 3: Copy in the chars. Transform the "-" to "+", and "*" to "/"
			for (int iter = 0; iter < len - 1; iter++)
			{
				char c = input[iter];

				switch (c)
				{
					case '-':
						base64Chars[iter] = '+';
						break;

					case '_':
						base64Chars[iter] = '/';
						break;

					default:
						base64Chars[iter] = c;
						break;
				}
			}

			////////////////////////////////////////////////////////
			// Step 4: Add padding chars
			for (int iter = len - 1; iter < base64Chars.Length; iter++)
			{
				base64Chars[iter] = '=';
			}

			// Do the actual conversion
			return Convert.FromBase64CharArray(base64Chars, 0, base64Chars.Length);
		}// FromB64()

		/* base64 web-safe encoding (padless) from RFC 4648 - https://tools.ietf.org/html/rfc4648#section-5 */
		public static string ToB64Url(this byte[] input)
		{
			return input.AsArraySegment().ToB64Url();
		}// ToB64Url()

		public static string ToB64Url(this ArraySegment<byte> inputSegment)
		{
			string b64str = inputSegment.ToB64();
			return b64str.Substring(0, b64str.Length - 1);
		}// ToB64Url()

		public static byte[] FromB64Url(this string str)
		{
			int lengthMod4 = str.Length % 4;
			string b64str = str + (lengthMod4 == 2 ? "2" : lengthMod4 == 3 ? "1" : "0");
			return b64str.FromB64();
		}// FromB64Url()
	}//class B64Extensions
}//ns