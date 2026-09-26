using System.Security.Cryptography;

namespace OfficeSecurity.Policy;

/// <summary>Signs policy documents on the server. The caller owns the key and its storage.</summary>
public sealed class PolicySigner
{
    private readonly ECDsa _key;
    private readonly string _keyId;

    public PolicySigner(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.KeySize != 256)
        {
            throw new ArgumentException("Policy signing key must be ECDSA P-256.", nameof(key));
        }

        _key = key;
        _keyId = PolicyKeys.ComputeKeyId(key.ExportSubjectPublicKeyInfo());
    }

    public string KeyId => _keyId;

    public SignedPolicyEnvelope Sign(SecurityPolicyDocument document)
    {
        PolicyDocumentValidator.ThrowIfInvalid(document);
        var payload = PolicySerializer.ToUtf8Bytes(document);
        var signature = _key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignedPolicyEnvelope(_keyId, payload, signature);
    }
}

public static class PolicyKeys
{
    public static string ComputeKeyId(ReadOnlySpan<byte> subjectPublicKeyInfo) =>
        Convert.ToHexStringLower(SHA256.HashData(subjectPublicKeyInfo));
}
