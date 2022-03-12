using System;
using System.Security.Cryptography;
using System.Linq;

namespace SecurityDriven.Inferno.Extensions
{
	public static class CngKeyExtensions
	{
#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		static readonly CngKeyCreationParameters cngKeyCreationParameters = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport };

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		static readonly CngProperty exportPolicy_AllowPlaintextExport = new CngProperty("Export Policy", BitConverter.GetBytes((int)CngExportPolicies.AllowPlaintextExport), CngPropertyOptions.None);

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static CngKey CreateNewDhmKey(string name = null)
		{
			return CngKey.Create(CngAlgorithm.ECDiffieHellmanP384, name, cngKeyCreationParameters);
		}

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static CngKey CreateNewDsaKey(string name = null)
		{
			return CngKey.Create(CngAlgorithm.ECDsaP384, name, cngKeyCreationParameters);
		}

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static byte[] GetPrivateBlob(this CngKey key)
		{
			return key.Export(CngKeyBlobFormat.EccPrivateBlob);
		}

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static byte[] GetPublicBlob(this CngKey key)
		{
			return key.Export(CngKeyBlobFormat.EccPublicBlob);
		}

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static CngKey ToPrivateKeyFromBlob(this byte[] privateBlob)
		{
			var key = CngKey.Import(privateBlob, CngKeyBlobFormat.EccPrivateBlob);
			key.SetProperty(exportPolicy_AllowPlaintextExport);
			return key;
		}

#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static CngKey ToPublicKeyFromBlob(this byte[] publicBlob)
		{
			return CngKey.Import(publicBlob, CngKeyBlobFormat.EccPublicBlob);
		}

		/// <summary>
		/// Both parties are static and authenticated.
		/// </summary>
#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
		public static byte[] GetSharedDhmSecret(this CngKey privateDhmKey, CngKey publicDhmKey, byte[] contextAppend = null, byte[] contextPrepend = null)
		{
#if (NET462 || NETCOREAPP3_1 || NET5_0 || NET6_0)
			using (var ecdh = new ECDiffieHellmanCng(privateDhmKey) { HashAlgorithm = CngAlgorithm.Sha384, SecretAppend = contextAppend, SecretPrepend = contextPrepend })
				return ecdh.DeriveKeyMaterial(publicDhmKey);
#elif NETSTANDARD2_0
			throw new PlatformNotSupportedException($"ECDiffieHellman is not supported on .NET Standard 2.0. Please reference \"{typeof(CngKeyExtensions).Assembly.GetName().Name}\" from .NET Framework or .NET Core for ECDiffieHellman support.");
#else
#error Unknown target
#endif
		}// GetSharedDhmSecret()

		/// <summary>
		/// Sender is anonymous and keyless.
		/// Receiver is static and authenticated.
		/// </summary>
#if NET5_0_OR_GREATER
		[System.Runtime.Versioning.SupportedOSPlatform("windows")]
#elif NETSTANDARD2_0_OR_GREATER || NET461_OR_GREATER || NETCOREAPP3_1
#else
#error Target Framework is not supported
#endif
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