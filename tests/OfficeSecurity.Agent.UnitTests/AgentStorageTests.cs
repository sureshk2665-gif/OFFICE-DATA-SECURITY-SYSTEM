using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

public sealed class AgentStorageTests
{
    [Fact]
    public void Event_store_keeps_events_across_restarts_until_uploaded()
    {
        using var dir = new TempDirectory();
        var paths = new AgentPaths(dir.Path);
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var store = new PendingEventStore(paths, clock);
        store.Enqueue(SecurityEventType.DeviceConnected, EventSeverities.Information, "first");
        clock.Advance(TimeSpan.FromSeconds(1));
        store.Enqueue(SecurityEventType.PolicyApplied, EventSeverities.Information, "second");

        var reopened = new PendingEventStore(paths, clock);
        var pending = reopened.PeekPending(10);
        Assert.Equal(["first", "second"], pending.Select(e => e.Details));

        reopened.MarkUploaded([pending[0].EventId]);
        Assert.Equal(1, reopened.PendingCount());
        Assert.Equal("second", Assert.Single(reopened.PeekPending(10)).Details);
    }

    [Fact]
    public void Event_store_discards_oldest_events_beyond_its_limit()
    {
        using var dir = new TempDirectory();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var store = new PendingEventStore(new AgentPaths(dir.Path), clock, maxPending: 3);

        for (var i = 1; i <= 5; i++)
        {
            store.Enqueue(SecurityEventType.DeviceConnected, EventSeverities.Information, $"event {i}");
            clock.Advance(TimeSpan.FromSeconds(1));
        }

        Assert.Equal(["event 3", "event 4", "event 5"], store.PeekPending(10).Select(e => e.Details));
    }

    [Fact]
    public void Policy_cache_accepts_only_unmodified_policy_for_this_computer_and_key()
    {
        using var dir = new TempDirectory();
        var paths = new AgentPaths(dir.Path);
        Directory.CreateDirectory(dir.Path);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var computerId = Guid.NewGuid();
        var cache = new PolicyCache(paths);
        cache.Save(new PolicySigner(key).Sign(new PolicySettings().ToDocument(computerId, 7, DateTimeOffset.UtcNow)));

        Assert.Equal(7, cache.Load(new PolicyVerifier(key.ExportSubjectPublicKeyInfo()), computerId)!.Document!.Version);
        Assert.Equal(PolicyRejectionReason.UnknownSigningKey, cache.Load(new PolicyVerifier(otherKey.ExportSubjectPublicKeyInfo()), computerId)!.Reason);
        Assert.Equal(PolicyRejectionReason.WrongComputer, cache.Load(new PolicyVerifier(key.ExportSubjectPublicKeyInfo()), Guid.NewGuid())!.Reason);

        File.WriteAllText(paths.PolicyCacheFile, "{ not json");
        Assert.Equal(PolicyRejectionReason.MalformedDocument, cache.Load(new PolicyVerifier(key.ExportSubjectPublicKeyInfo()), computerId)!.Reason);
    }

    [Fact]
    public void File_key_store_keeps_the_same_key_and_builds_a_usable_client_certificate()
    {
        using var dir = new TempDirectory();
        var store = new FileDeviceKeyStore(dir.Path);
        using var key = store.GetOrCreate("computer-key");
        using var again = store.GetOrCreate("computer-key");
        Assert.Equal(key.ExportSubjectPublicKeyInfo(), again.ExportSubjectPublicKeyInfo());

        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        using var selfSigned = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var client = store.CreateClientCertificate("computer-key", selfSigned.ExportCertificatePem());
        Assert.True(client.HasPrivateKey);

        store.Delete("computer-key");
        using var fresh = store.GetOrCreate("computer-key");
        Assert.NotEqual(key.ExportSubjectPublicKeyInfo(), fresh.ExportSubjectPublicKeyInfo());
    }

    [WindowsFact(requiresAdministrator: true)]
    public void Windows_machine_key_is_persistent_and_not_exportable()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var store = new CngDeviceKeyStore();
        var name = "OfficeSecurityTest-" + Guid.NewGuid().ToString("N");
        try
        {
            using var key = store.GetOrCreate(name);
            using var reopened = store.GetOrCreate(name);
            Assert.Equal(key.ExportSubjectPublicKeyInfo(), reopened.ExportSubjectPublicKeyInfo());
            Assert.ThrowsAny<CryptographicException>(() => key.ExportPkcs8PrivateKey());

            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
            using var selfSigned = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            using var client = store.CreateClientCertificate(name, selfSigned.ExportCertificatePem());
            Assert.True(client.HasPrivateKey);
        }
        finally
        {
            store.Delete(name);
        }
    }
}
