using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Server.Application.Abstractions;

namespace OfficeSecurity.Server.Infrastructure.Certificates;

/// <summary>Issues client certificates to approved computers from the server's private CA.</summary>
public sealed class DeviceCertificateAuthority(ServerCertificates certificates, TimeProvider clock) : IDeviceCertificateAuthority
{
    public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(730);

    public byte[] CaCertificateDer => certificates.CaCertificate.RawData;

    public string? ValidateRequest(string certificateRequestPem)
    {
        try
        {
            var request = CertificateRequest.LoadSigningRequestPem(certificateRequestPem, HashAlgorithmName.SHA256);
            using var key = request.PublicKey.GetECDsaPublicKey();
            return key is { KeySize: 256 } ? null : "The certificate request must use an ECDSA P-256 key.";
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return "The certificate request is not valid.";
        }
    }

    public IssuedCertificate IssueComputerCertificate(string certificateRequestPem, Guid computerId)
    {
        // Signature of the request is verified here, proving the agent holds the private key.
        var submitted = CertificateRequest.LoadSigningRequestPem(certificateRequestPem, HashAlgorithmName.SHA256);
        var subject = new X500DistinguishedName($"CN={computerId:D}, OU=Computers, O=Office Computer Security System");
        var request = new CertificateRequest(subject, submitted.PublicKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ClientAuthenticationOid, "Client Authentication")], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(certificates.CaWithPrivateKey, includeKeyIdentifier: true, includeIssuerAndSerial: false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"urn:office-security:computer:{computerId:D}"));
        request.CertificateExtensions.Add(san.Build());

        var now = clock.GetUtcNow();
        var notAfter = now + Lifetime;
        if (notAfter > certificates.CaWithPrivateKey.NotAfter)
        {
            notAfter = certificates.CaWithPrivateKey.NotAfter;
        }

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var issued = request.Create(certificates.CaWithPrivateKey, now.AddMinutes(-5), notAfter, serial);
        return new IssuedCertificate(issued.ExportCertificatePem(), Thumbprint(issued), notAfter);
    }

    /// <summary>SHA-256 certificate thumbprint in lower-case hex; how the server identifies a computer.</summary>
    public static string Thumbprint(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
    }

    /// <summary>True if the certificate was issued by this server's CA, is currently valid, and allows client authentication.</summary>
    public bool IsIssuedByThisCa(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(certificates.CaCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = clock.GetUtcNow().UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationOid));
        return chain.Build(certificate) &&
               chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(certificates.CaCertificate.RawData);
    }
}
