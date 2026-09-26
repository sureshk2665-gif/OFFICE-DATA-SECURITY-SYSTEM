namespace OfficeSecurity.Server.Application.Abstractions;

public sealed record IssuedCertificate(string CertificatePem, string Thumbprint, DateTimeOffset ExpiresAtUtc);

/// <summary>Issues and checks the client certificates that identify computers (mutual TLS).</summary>
public interface IDeviceCertificateAuthority
{
    /// <summary>Validates a PKCS#10 request (P-256 ECDSA, valid signature) and returns an error message, or null.</summary>
    string? ValidateRequest(string certificateRequestPem);

    IssuedCertificate IssueComputerCertificate(string certificateRequestPem, Guid computerId);

    /// <summary>The CA certificate (DER), for computing the pairing code.</summary>
    byte[] CaCertificateDer { get; }
}

/// <summary>Signs effective policies for agents.</summary>
public interface IPolicySigningService
{
    /// <summary>Base64 SubjectPublicKeyInfo; agents pin it at enrollment.</summary>
    string PublicKeyBase64 { get; }

    OfficeSecurity.Policy.SignedPolicyEnvelope Sign(OfficeSecurity.Policy.SecurityPolicyDocument document);
}
