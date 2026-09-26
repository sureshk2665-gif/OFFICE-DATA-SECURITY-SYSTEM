using System.Security.Cryptography;
using System.Text.Json;

namespace OfficeSecurity.Policy;

public enum PolicyRejectionReason
{
    None = 0,
    UnknownSigningKey,
    InvalidSignature,
    MalformedDocument,
    UnsupportedSchemaVersion,
    WrongComputer,
    NotNewerThanCurrent,
    InvalidContent,
}

public sealed record PolicyVerificationResult(SecurityPolicyDocument? Document, PolicyRejectionReason Reason, string? Detail)
{
    public bool IsValid => Reason == PolicyRejectionReason.None && Document is not null;

    internal static PolicyVerificationResult Reject(PolicyRejectionReason reason, string detail) => new(null, reason, detail);
}

/// <summary>
/// Verifies signed policies on the agent against the pinned server policy key. Any failure means the
/// agent keeps enforcing its last valid policy.
/// </summary>
public sealed class PolicyVerifier
{
    private readonly byte[] _trustedPublicKey;
    private readonly string _trustedKeyId;

    /// <param name="trustedSubjectPublicKeyInfo">The pinned policy-signing public key (X.509 SubjectPublicKeyInfo DER).</param>
    public PolicyVerifier(byte[] trustedSubjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(trustedSubjectPublicKeyInfo);
        using var probe = ECDsa.Create();
        probe.ImportSubjectPublicKeyInfo(trustedSubjectPublicKeyInfo, out _);
        if (probe.KeySize != 256)
        {
            throw new ArgumentException("Policy signing key must be ECDSA P-256.", nameof(trustedSubjectPublicKeyInfo));
        }

        _trustedPublicKey = (byte[])trustedSubjectPublicKeyInfo.Clone();
        _trustedKeyId = PolicyKeys.ComputeKeyId(_trustedPublicKey);
    }

    /// <param name="envelope">Signed policy received from the server or read from the local cache.</param>
    /// <param name="expectedComputerId">This computer's enrolled identity.</param>
    /// <param name="currentVersion">Version currently enforced, or <c>null</c> when re-validating the cache itself.</param>
    public PolicyVerificationResult Verify(SignedPolicyEnvelope envelope, Guid expectedComputerId, long? currentVersion)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        if (!string.Equals(envelope.KeyId, _trustedKeyId, StringComparison.Ordinal))
        {
            return PolicyVerificationResult.Reject(PolicyRejectionReason.UnknownSigningKey, "Policy was signed with an untrusted key.");
        }

        using (var key = ECDsa.Create())
        {
            key.ImportSubjectPublicKeyInfo(_trustedPublicKey, out _);
            if (envelope.Payload is null || envelope.Signature is null ||
                !key.VerifyData(envelope.Payload, envelope.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return PolicyVerificationResult.Reject(PolicyRejectionReason.InvalidSignature, "Policy signature is invalid.");
            }
        }

        SecurityPolicyDocument document;
        try
        {
            document = PolicySerializer.FromUtf8Bytes(envelope.Payload);
        }
        catch (JsonException ex)
        {
            return PolicyVerificationResult.Reject(PolicyRejectionReason.MalformedDocument, ex.Message);
        }

        if (document.SchemaVersion != SecurityPolicyDocument.CurrentSchemaVersion)
        {
            return PolicyVerificationResult.Reject(PolicyRejectionReason.UnsupportedSchemaVersion, $"Schema version {document.SchemaVersion} is not supported.");
        }

        if (document.ComputerId != expectedComputerId)
        {
            return PolicyVerificationResult.Reject(PolicyRejectionReason.WrongComputer, "Policy targets a different computer.");
        }

        if (currentVersion is { } current && document.Version <= current)
        {
            return PolicyVerificationResult.Reject(PolicyRejectionReason.NotNewerThanCurrent, $"Policy version {document.Version} is not newer than {current}.");
        }

        var errors = PolicyDocumentValidator.Validate(document);
        if (errors.Count > 0)
        {
            return PolicyVerificationResult.Reject(PolicyRejectionReason.InvalidContent, string.Join("; ", errors));
        }

        return new PolicyVerificationResult(document, PolicyRejectionReason.None, null);
    }
}
