using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Infrastructure.Certificates;

namespace OfficeSecurity.Server.UnitTests;

public sealed class CertificateAuthorityTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ocss-ca-" + Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 9, 26, 0, 0, 0, TimeSpan.Zero));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private ServerCertificateAuthority CreateCa() => new(_dir, new XorProtector(), _clock);

    [Fact]
    public void Server_certificate_chains_to_the_ca_and_covers_host_names()
    {
        var certs = CreateCa().LoadOrCreate(["office-server.local"]);
        using var server = X509CertificateLoader.LoadPkcs12(certs.ServerCertificatePfx, null);

        Assert.True(server.HasPrivateKey);
        Assert.False(certs.CaCertificate.HasPrivateKey);

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(certs.CaCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = _clock.GetUtcNow().UtcDateTime.AddHours(1);
        Assert.True(chain.Build(server), string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation)));

        var san = server.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        Assert.Contains("office-server.local", san.EnumerateDnsNames());
        Assert.Contains("localhost", san.EnumerateDnsNames());
        Assert.Contains(san.EnumerateIPAddresses(), ip => ip.ToString() == "127.0.0.1");
    }

    [Fact]
    public void Private_keys_are_not_stored_in_plain_form()
    {
        CreateCa().LoadOrCreate();

        foreach (var file in Directory.GetFiles(_dir, "*.protected"))
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => X509CertificateLoader.LoadPkcs12FromFile(file, null));
        }
    }

    [Fact]
    public void Restart_reuses_the_same_ca_and_server_certificate()
    {
        var first = CreateCa().LoadOrCreate();
        var second = CreateCa().LoadOrCreate();

        Assert.Equal(first.CaCertificate.Thumbprint, second.CaCertificate.Thumbprint);
        Assert.Equal(first.ServerCertificatePfx, second.ServerCertificatePfx);
    }

    [Fact]
    public void New_host_name_or_near_expiry_issues_new_server_certificate_with_same_ca()
    {
        var first = CreateCa().LoadOrCreate();

        var renamed = CreateCa().LoadOrCreate(["new-name.local"]);
        Assert.Equal(first.CaCertificate.Thumbprint, renamed.CaCertificate.Thumbprint);
        Assert.NotEqual(first.ServerCertificatePfx, renamed.ServerCertificatePfx);

        _clock.Advance(TimeSpan.FromDays(380));
        var renewed = CreateCa().LoadOrCreate(["new-name.local"]);
        Assert.Equal(first.CaCertificate.Thumbprint, renewed.CaCertificate.Thumbprint);
        Assert.NotEqual(renamed.ServerCertificatePfx, renewed.ServerCertificatePfx);
    }

    /// <summary>Test stand-in for DPAPI: reversible, but makes the stored bytes unreadable as PFX.</summary>
    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Select(b => (byte)(b ^ 0x5A)).ToArray();

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }
}
