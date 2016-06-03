using System;
using System.Security.Cryptography;

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
			using (var ecdh = new ECDiffieHellmanCng(privateDhmKey) { HashAlgorithm = CngAlgorithm.Sha384, SecretAppend = contextAppend, SecretPrepend = contextPrepend })
				return ecdh.DeriveKeyMaterial(publicDhmKey);
		}

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

	public class SharedEphemeralBundle
	{
		public byte[] SharedSecret;
		public byte[] EphemeralDhmPublicKeyBlob;
	}//class SharedEphemeralDhmSecret
}//ns