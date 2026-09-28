using System.Security.Cryptography;
using OfficeSecurity.Policy;
using OfficeSecurity.Server.Application.Abstractions;

namespace OfficeSecurity.Server.Infrastructure.Certificates;

/// <summary>
/// The policy signing key (ECDSA P-256), separate from the TLS CA (ADR-0003). Created on first start and
/// stored only in encrypted form.
/// </summary>
public sealed class PolicySigningService : IPolicySigningService, IDisposable
{
    private const string KeyFile = "policy-signing.key.protected";
    private readonly ECDsa _key;
    private readonly PolicySigner _signer;

    public PolicySigningService(string certificateDirectory, ISecretProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        Directory.CreateDirectory(certificateDirectory);
        var path = Path.Combine(certificateDirectory, KeyFile);
        _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            _key.ImportPkcs8PrivateKey(protector.Unprotect(File.ReadAllBytes(path)), out _);
        }
        else
        {
            var temp = path + ".tmp";
            File.WriteAllBytes(temp, protector.Protect(_key.ExportPkcs8PrivateKey()));
            File.Move(temp, path, overwrite: false);
        }

        _signer = new PolicySigner(_key);
        PublicKeyBase64 = Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());
    }

    public string PublicKeyBase64 { get; }

    public SignedPolicyEnvelope Sign(SecurityPolicyDocument document) => _signer.Sign(document);

    public byte[] SignData(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public void Dispose() => _key.Dispose();
}
