using System;
using System.Diagnostics;

namespace SecurityDriven.Inferno.Otp
{
	using SecurityDriven.Inferno.Mac;
	using SecurityDriven.Inferno.Extensions;
	using Utils = SecurityDriven.Inferno.Utils;

	public static class TOTP
	{
		static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		static readonly long _timeStepTicks = TimeSpan.FromSeconds(30).Ticks;
		static readonly Func<HMAC2> _hmacFactory = HMACFactories.HMACSHA1;
		static readonly Func<DateTime> _timeFactory = () => DateTime.UtcNow;
		static readonly int[] _totpModulos = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
		const int DEFAULT_TOTP_LENGTH = 6;

		#region private
		// https://tools.ietf.org/html/rfc6238
		static int ComputeTotp(byte[] secret, long timeStepNumber, int totpLength, string modifier)
		{
			if (secret == null) throw new ArgumentNullException(nameof(secret));

			byte[] timestepAsBytes = new byte[sizeof(long)], hash = null;
			new Utils.LongStruct { LongValue = timeStepNumber }.ToBEBytes(timestepAsBytes);

			using (var hmac = _hmacFactory())
			{
				hmac.Key = secret;

				hmac.TransformBlock(timestepAsBytes, 0, timestepAsBytes.Length, null, 0);
				if (!String.IsNullOrEmpty(modifier))
				{
					byte[] modifierbytes = modifier.ToBytes();
					hmac.TransformBlock(modifierbytes, 0, modifierbytes.Length, null, 0);
				}
                hmac.TransformFinalBlock(timestepAsBytes, 0, 0);
				hash = hmac.HashInner; // do not dispose hmac before 'hash' access --> will zero-out internal array

				// Generate dynamically-truncated string
				var offset = hash[hash.Length - 1] & 0x0F;
				Debug.Assert(offset + 4 < hash.Length);
				var binaryCode = (hash[offset] & 0x7F) << 24
								 | (hash[offset + 1]) << 16
								 | (hash[offset + 2]) << 8
								 | (hash[offset + 3]);

				return binaryCode % _totpModulos[totpLength];
			}//using
		}//ComputeTotp()

		//https://tools.ietf.org/html/rfc6238#section-4
		static long GetCurrentTimeStepNumber(Func<DateTime> timeFactory)
		{
			var time = timeFactory();
			if (time.Kind == DateTimeKind.Local) throw new ArgumentException("DateTime cannot of 'Local' kind.", nameof(timeFactory));
			var deltaTicks = (time - _unixEpoch).Ticks;
			var timeStepNumber = deltaTicks / _timeStepTicks;
			//Console.WriteLine(string.Format("Remaining ticks: {0}", TimeSpan.FromTicks(_timeStepTicks - deltaTicks % _timeStepTicks)));

			return timeStepNumber;
		}//GetCurrentTimeStepNumber()
		#endregion

		#region public
		public static int GenerateTOTP(byte[] secret, Func<DateTime> timeFactory = null, int totpLength = DEFAULT_TOTP_LENGTH, string modifier = null)
		{
			if (timeFactory == null) timeFactory = _timeFactory;
			long currentTimeStep = GetCurrentTimeStepNumber(timeFactory);

			return ComputeTotp(secret, currentTimeStep, totpLength, modifier);
		}//GenerateTOTP()

		public static bool ValidateTOTP(byte[] secret, int totp, Func<DateTime> timeFactory = null, int totpLength = DEFAULT_TOTP_LENGTH, string modifier = null)
		{
			if (timeFactory == null) timeFactory = _timeFactory;
			long currentTimeStep = GetCurrentTimeStepNumber(timeFactory);

			bool result = false;
			for (int i = -1; i <= 1; ++i)
			{
				int computedTotp = ComputeTotp(secret, currentTimeStep + i, totpLength, modifier);
				result |= totp == computedTotp;
			}
			return result;
		}//ValidateTOTP()
		#endregion
	}//class TOTP
}//ns