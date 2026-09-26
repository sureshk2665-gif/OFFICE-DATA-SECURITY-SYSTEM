using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

/// <summary>The agent over real HTTPS with client certificates (Kestrel), as on an office network.</summary>
public sealed class MutualTlsTests
{
    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static ServerFactory StartKestrel()
    {
        var server = new ServerFactory { HttpsPort = FreePort() };
        server.StartRealHttps();
        return server;
    }

    private static HttpClient AdminClient(ServerFactory server, string token) => server.Client(token);

    [Fact]
    public async Task Agent_enrolls_and_reports_over_mutual_tls()
    {
        await using var server = StartKestrel();
        var owner = await server.OwnerTokenAsync();
        using var admin = AdminClient(server, owner);

        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin, useRealTls: true);
        await agent.StepAsync();

        var detail = await admin.GetFromJsonAsync<ComputerDetail>(ApiRoutes.ComputerById(agent.ComputerId));
        Assert.True(detail!.Summary.IsOnline);
        Assert.Equal(1, agent.Runtime.CurrentPolicy.Version);
        Assert.NotNull(detail.CertificateThumbprint);
    }

    [Fact]
    public async Task Foreign_client_certificate_is_refused_over_tls()
    {
        await using var server = StartKestrel();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var foreign = new CertificateRequest("CN=intruder", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var exportable = OperatingSystem.IsWindows()
            ? X509CertificateLoader.LoadPkcs12(foreign.Export(X509ContentType.Pkcs12), null)
            : X509CertificateLoader.LoadPkcs12(foreign.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.EphemeralKeySet);
        var ca = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(server.DataDirectory, "certificates", "office-security-ca.cer"));
        using var client = AgentServerClient.Create(new Uri($"https://localhost:{server.HttpsPort}"), ca, exportable);

        var failure = await Assert.ThrowsAsync<AgentServerException>(() => client.HeartbeatAsync(new AgentHeartbeatRequest("x", 0, [], 0), CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, failure.StatusCode);
    }
}
