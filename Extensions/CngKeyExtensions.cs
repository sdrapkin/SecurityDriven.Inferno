using System;
using System.Security.Cryptography;
using System.Linq;

namespace SecurityDriven.Inferno.Extensions
{
	public static class CngKeyExtensions
	{
		static readonly CngKeyCreationParameters cngKeyCreationParameters = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport };
		static readonly CngProperty exportPolicy_AllowPlaintextExport = new CngProperty("Export Policy", BitConverter.GetBytes((int)CngExportPolicies.AllowPlaintextExport), CngPropertyOptions.None);

		public static CngKey CreateNewDhmKey(string name = null)
		{
			return CngKey.Create(CngAlgorithm.ECDiffieHellmanP384, name, cngKeyCreationParameters);
		}

		public static CngKey CreateNewDsaKey(string name = null)
		{
			return CngKey.Create(CngAlgorithm.ECDsaP384, name, cngKeyCreationParameters);
		}

		public static byte[] GetPrivateBlob(this CngKey key)
		{
			return key.Export(CngKeyBlobFormat.EccPrivateBlob);
		}

		public static byte[] GetPublicBlob(this CngKey key)
		{
			return key.Export(CngKeyBlobFormat.EccPublicBlob);
		}

		public static CngKey ToPrivateKeyFromBlob(this byte[] privateBlob)
		{
			var key = CngKey.Import(privateBlob, CngKeyBlobFormat.EccPrivateBlob);
			key.SetProperty(exportPolicy_AllowPlaintextExport);
			return key;
		}

		public static CngKey ToPublicKeyFromBlob(this byte[] publicBlob)
		{
			return CngKey.Import(publicBlob, CngKeyBlobFormat.EccPublicBlob);
		}

		/// <summary>
		/// Both parties are static and authenticated.
		/// </summary>
		public static byte[] GetSharedDhmSecret(this CngKey privateDhmKey, CngKey publicDhmKey, byte[] contextAppend = null, byte[] contextPrepend = null)
		{
#if NET462
			using (var ecdh = new ECDiffieHellmanCng(privateDhmKey) { HashAlgorithm = CngAlgorithm.Sha384, SecretAppend = contextAppend, SecretPrepend = contextPrepend })
				return ecdh.DeriveKeyMaterial(publicDhmKey);
#elif NETCOREAPP2_1

			const int P384_POINT_BYTELENGTH = 48;
			var privateDhmKeyBytes = new ArraySegment<byte>(privateDhmKey.GetPrivateBlob(),
				8 /* [4-byte magic] [4-byte length] */,
				P384_POINT_BYTELENGTH * 3 /* [X] [Y] [D] */
				);
			var ecParameters_fromPrivateDhmKey = new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP384,
				Q = new ECPoint
				{
					X = privateDhmKeyBytes.Skip(00).Take(P384_POINT_BYTELENGTH).ToArray(),
					Y = privateDhmKeyBytes.Skip(P384_POINT_BYTELENGTH).Take(P384_POINT_BYTELENGTH).ToArray()
				},
				D = privateDhmKeyBytes.Skip(P384_POINT_BYTELENGTH * 2).Take(P384_POINT_BYTELENGTH).ToArray()
			};

			var publicDhmKeyBytes = new ArraySegment<byte>(publicDhmKey.GetPublicBlob(),
				8 /* [4-byte magic] [4-byte length] */,
				P384_POINT_BYTELENGTH * 2 /* [X] [Y] only */
				);
			var ecParameters_fromPublicDhmKey = new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP384,
				Q = new ECPoint
				{
					X = publicDhmKeyBytes.Skip(00).Take(P384_POINT_BYTELENGTH).ToArray(),
					Y = privateDhmKeyBytes.Skip(P384_POINT_BYTELENGTH).Take(P384_POINT_BYTELENGTH).ToArray()
				},
			};

			using (var ecdh_source = ECDiffieHellman.Create(ecParameters_fromPrivateDhmKey))
			using (var ecdh_target = ECDiffieHellman.Create(ecParameters_fromPublicDhmKey))
			{
				return ecdh_source.DeriveKeyFromHash(
					otherPartyPublicKey: ecdh_target.PublicKey,
					hashAlgorithm: HashAlgorithmName.SHA384,
					secretPrepend: contextPrepend,
					secretAppend: contextAppend
					);
			}
#endif
		}// GetSharedDhmSecret()

		/// <summary>
		/// Sender is anonymous and keyless.
		/// Receiver is static and authenticated.
		/// </summary>
		public static SharedEphemeralBundle GetSharedEphemeralDhmSecret(this CngKey receiverDhmPublicKey, byte[] contextAppend = null, byte[] contextPrepend = null)
		{
			using (var sender = CreateNewDhmKey())
				return new SharedEphemeralBundle { SharedSecret = sender.GetSharedDhmSecret(receiverDhmPublicKey, contextAppend, contextPrepend), EphemeralDhmPublicKeyBlob = sender.GetPublicBlob() };
		}
	}//class CngKeyExtensions

	public class SharedEphemeralBundle : IDisposable
	{
		public byte[] SharedSecret;
		public byte[] EphemeralDhmPublicKeyBlob;

		#region IDisposable

		void Internal_Dispose()
		{
			var sharedSecret = this.SharedSecret;
			if (sharedSecret != null)
			{
				Array.Clear(sharedSecret, 0, sharedSecret.Length);
				this.SharedSecret = null;
			}
		}// Internal_Dispose()

		public void Dispose()
		{
			GC.SuppressFinalize(this);
			this.Internal_Dispose();
		}// Dispose()

		~SharedEphemeralBundle() => Internal_Dispose();
		#endregion

	}//class SharedEphemeralDhmSecret
}//ns