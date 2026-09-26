using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OfficeSecurity.Agent.Core;

/// <summary>Holds the computer's private key, which never leaves the computer.</summary>
public interface IDeviceKeyStore
{
    /// <summary>Human-readable description of where keys are kept, for status output.</summary>
    string Description { get; }

    ECDsa GetOrCreate(string keyName);

    void Delete(string keyName);

    /// <summary>Combines the issued certificate with the private key into a certificate usable for mutual TLS.</summary>
    X509Certificate2 CreateClientCertificate(string keyName, string certificatePem);
}

/// <summary>
/// Windows key storage: a non-exportable machine key in the TPM when available (Microsoft Platform
/// Crypto Provider), otherwise in the Microsoft Software Key Storage Provider. Only SYSTEM and
/// Administrators can use machine keys created by the service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CngDeviceKeyStore : IDeviceKeyStore
{
    private static readonly CngProvider[] Providers = [CngProvider.MicrosoftPlatformCryptoProvider, CngProvider.MicrosoftSoftwareKeyStorageProvider];

    public string Description { get; private set; } = "Windows machine key store";

    public ECDsa GetOrCreate(string keyName)
    {
        foreach (var provider in Providers)
        {
            if (CngKey.Exists(keyName, provider, CngKeyOpenOptions.MachineKey))
            {
                Description = Describe(provider);
                return new ECDsaCng(CngKey.Open(keyName, provider, CngKeyOpenOptions.MachineKey));
            }
        }

        foreach (var provider in Providers)
        {
            try
            {
                var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                });
                Description = Describe(provider);
                return new ECDsaCng(key);
            }
            catch (CryptographicException) when (provider == CngProvider.MicrosoftPlatformCryptoProvider)
            {
                // No usable TPM (common on virtual machines); fall back to the software provider.
            }
        }

        throw new CryptographicException("Could not create the computer key.");
    }

    public void Delete(string keyName)
    {
        foreach (var provider in Providers)
        {
            if (CngKey.Exists(keyName, provider, CngKeyOpenOptions.MachineKey))
            {
                using var key = CngKey.Open(keyName, provider, CngKeyOpenOptions.MachineKey);
                key.Delete();
            }
        }
    }

    public X509Certificate2 CreateClientCertificate(string keyName, string certificatePem)
    {
        using var publicOnly = X509Certificate2.CreateFromPem(certificatePem);
        using var key = GetOrCreate(keyName);
        // The certificate links to the persisted machine key, which Windows TLS (SChannel) can use directly.
        return publicOnly.CopyWithPrivateKey(key);
    }

    private static string Describe(CngProvider provider) =>
        provider == CngProvider.MicrosoftPlatformCryptoProvider ? "TPM (hardware-protected machine key)" : "Windows machine key store (software)";
}

/// <summary>
/// Key storage in a protected folder, for development and automated tests. Not used by the installed
/// Windows service.
/// </summary>
public sealed class FileDeviceKeyStore(string directory) : IDeviceKeyStore
{
    public string Description => "Key file (development/test only)";

    public ECDsa GetOrCreate(string keyName)
    {
        var path = PathFor(keyName);
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            key.ImportFromPem(File.ReadAllText(path));
            return key;
        }

        Directory.CreateDirectory(directory);
        File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return key;
    }

    public void Delete(string keyName) => File.Delete(PathFor(keyName));

    public X509Certificate2 CreateClientCertificate(string keyName, string certificatePem)
    {
        using var publicOnly = X509Certificate2.CreateFromPem(certificatePem);
        using var key = GetOrCreate(keyName);
        using var withKey = publicOnly.CopyWithPrivateKey(key);
        // Windows TLS cannot use in-memory (ephemeral) keys, so round-trip through PKCS#12 into a key container.
        return OperatingSystem.IsWindows()
            ? X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.DefaultKeySet)
            : X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.EphemeralKeySet);
    }

    private string PathFor(string keyName)
    {
        if (keyName.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
        {
            throw new ArgumentException("Invalid key name.", nameof(keyName));
        }

        return Path.Combine(directory, keyName + ".pem");
    }
}
