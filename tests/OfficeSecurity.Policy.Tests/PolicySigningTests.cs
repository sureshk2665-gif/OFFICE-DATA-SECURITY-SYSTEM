using System.Security.Cryptography;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Policy.Tests;

public sealed class PolicySigningTests : IDisposable
{
    private static readonly Guid ComputerId = Guid.Parse("7d8a3b0e-2f4c-4e8e-9a61-3c1d2b5f9e10");

    private readonly ECDsa _serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly PolicySigner _signer;
    private readonly PolicyVerifier _verifier;

    public PolicySigningTests()
    {
        _signer = new PolicySigner(_serverKey);
        _verifier = new PolicyVerifier(_serverKey.ExportSubjectPublicKeyInfo());
    }

    public void Dispose() => _serverKey.Dispose();

    private static SecurityPolicyDocument CreatePolicy(long version = 5) => new()
    {
        Version = version,
        ComputerId = ComputerId,
        IssuedAtUtc = new DateTimeOffset(2026, 9, 26, 10, 0, 0, TimeSpan.Zero),
        RemovableStorage = new RemovableStorageSettings
        {
            Mode = EnforcementMode.Enforce,
            ApprovedDevices = [new ApprovedDevice(@"USBSTOR\DISK&VEN_KINGSTON&PROD_DT&REV_1.00\0019E06B9C85F9A0A7A2B0D1&0", "Accounts backup drive", null)],
        },
        FileProtection = new FileProtectionSettings
        {
            ProtectedFolders = [new ProtectedFolder(@"D:\Company\Finance", AuditAccess: true, ControlledFolderAccess: true)],
        },
    };

    [Fact]
    public void Valid_signed_policy_is_accepted_and_round_trips()
    {
        var original = CreatePolicy();
        var envelope = _signer.Sign(original);

        var result = _verifier.Verify(envelope, ComputerId, currentVersion: 4);

        Assert.True(result.IsValid, result.Detail);
        Assert.Equal(original.Version, result.Document!.Version);
        Assert.Equal(EnforcementMode.Enforce, result.Document.RemovableStorage.Mode);
        Assert.Equal(original.RemovableStorage.ApprovedDevices, result.Document.RemovableStorage.ApprovedDevices);
        Assert.Equal(original.FileProtection.ProtectedFolders, result.Document.FileProtection.ProtectedFolders);
    }

    [Fact]
    public void Modified_payload_is_rejected()
    {
        var envelope = _signer.Sign(CreatePolicy());
        var tampered = System.Text.Encoding.UTF8.GetBytes(
            System.Text.Encoding.UTF8.GetString(envelope.Payload).Replace("\"Enforce\"", "\"Off\"", StringComparison.Ordinal));

        var result = _verifier.Verify(envelope with { Payload = tampered }, ComputerId, currentVersion: null);

        Assert.Equal(PolicyRejectionReason.InvalidSignature, result.Reason);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Modified_signature_is_rejected()
    {
        var envelope = _signer.Sign(CreatePolicy());
        var signature = (byte[])envelope.Signature.Clone();
        signature[10] ^= 0xFF;

        var result = _verifier.Verify(envelope with { Signature = signature }, ComputerId, currentVersion: null);

        Assert.Equal(PolicyRejectionReason.InvalidSignature, result.Reason);
    }

    [Fact]
    public void Policy_signed_by_another_key_is_rejected()
    {
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = new PolicySigner(attackerKey).Sign(CreatePolicy());

        var result = _verifier.Verify(envelope, ComputerId, currentVersion: null);

        Assert.Equal(PolicyRejectionReason.UnknownSigningKey, result.Reason);
    }

    [Fact]
    public void Attacker_key_with_spoofed_key_id_is_rejected_by_signature_check()
    {
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = new PolicySigner(attackerKey).Sign(CreatePolicy()) with { KeyId = _signer.KeyId };

        var result = _verifier.Verify(envelope, ComputerId, currentVersion: null);

        Assert.Equal(PolicyRejectionReason.InvalidSignature, result.Reason);
    }

    [Fact]
    public void Policy_for_another_computer_is_rejected()
    {
        var envelope = _signer.Sign(CreatePolicy());

        var result = _verifier.Verify(envelope, Guid.NewGuid(), currentVersion: null);

        Assert.Equal(PolicyRejectionReason.WrongComputer, result.Reason);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(6)]
    public void Replayed_older_or_same_version_is_rejected(long currentVersion)
    {
        var envelope = _signer.Sign(CreatePolicy(version: 5));

        var result = _verifier.Verify(envelope, ComputerId, currentVersion);

        Assert.Equal(PolicyRejectionReason.NotNewerThanCurrent, result.Reason);
    }

    [Fact]
    public void Cached_policy_can_be_revalidated_without_version_check()
    {
        var envelope = _signer.Sign(CreatePolicy(version: 5));

        Assert.True(_verifier.Verify(envelope, ComputerId, currentVersion: null).IsValid);
    }

    [Fact]
    public void Signed_but_malformed_payload_is_rejected()
    {
        var payload = "{\"version\":1,\"unexpectedField\":true}"u8.ToArray();
        var signature = _serverKey.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var result = _verifier.Verify(new SignedPolicyEnvelope(_signer.KeyId, payload, signature), ComputerId, currentVersion: null);

        Assert.Equal(PolicyRejectionReason.MalformedDocument, result.Reason);
    }

    [Fact]
    public void Signer_refuses_invalid_policy()
    {
        var invalid = CreatePolicy() with { Agent = new AgentSettings { HeartbeatIntervalSeconds = 1 } };

        Assert.Throws<ArgumentException>(() => _signer.Sign(invalid));
    }

    [Fact]
    public void Signer_requires_p256_key()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        Assert.Throws<ArgumentException>(() => new PolicySigner(p384));
    }
}
