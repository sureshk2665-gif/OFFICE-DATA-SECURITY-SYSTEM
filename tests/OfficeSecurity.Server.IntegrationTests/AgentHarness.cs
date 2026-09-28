using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class TestInventory : IInventoryCollector
{
    public string ComputerName { get; set; } = "PC-" + Guid.NewGuid().ToString("N")[..6].ToUpperInvariant();

    public List<ConnectedDevice> Devices { get; } = [];

    public HardwareInventory CollectHardware() =>
        new(ComputerName, "Microsoft Windows 11 Pro", "24H2", "26100.4061", "Professional", "Contoso", "OfficeBook 5", "SN-1234", "Test CPU", 16384, 476, true, false, "WORKGROUP");

    public IReadOnlyList<ConnectedDevice> CollectDevices() => [.. Devices];

    public List<InstalledSoftware> Software { get; } = [];

    public IReadOnlyList<InstalledSoftware> CollectSoftware() => [.. Software];
}

/// <summary>
/// The real agent logic (AgentRuntime) connected to a test server. With <see cref="UseRealTls"/> the agent
/// uses its normal HTTPS client with a client certificate (mutual TLS) against a Kestrel server.
/// </summary>
public sealed class AgentHarness : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ocss-agent-it-" + Guid.NewGuid().ToString("N"));
    private readonly ServerFactory _server;

    public AgentHarness(ServerFactory server, string enrollmentCode, bool useRealTls = false)
    {
        _server = server;
        UseRealTls = useRealTls;
        Paths = new AgentPaths(_dir);
        Config = new AgentConfigStore(Paths, protectDirectory: false);
        Keys = new FileDeviceKeyStore(Paths.FileKeyDirectory);
        var caDer = File.ReadAllBytes(Path.Combine(server.DataDirectory, "certificates", "office-security-ca.cer"));
        Config.Save(new AgentConfig
        {
            State = AgentState.Enrolling,
            ServerAddress = useRealTls ? $"https://localhost:{server.HttpsPort}" : "https://localhost",
            CaCertificateBase64 = Convert.ToBase64String(caDer),
            EnrollmentCode = enrollmentCode,
        });
        Events = new PendingEventStore(Paths, server.Clock);
        Runtime = new AgentRuntime(
            Config, Keys, Inventory, new EnforcementCoordinator([], server.Clock), Events, new PolicyCache(Paths), server.Clock,
            NullLogger<AgentRuntime>.Instance, new AgentRuntimeOptions { AgentVersion = "1.2.3-test" },
            useRealTls ? null : InMemoryClient);
    }

    public bool UseRealTls { get; }

    public AgentPaths Paths { get; }

    public AgentConfigStore Config { get; }

    public FileDeviceKeyStore Keys { get; }

    public PendingEventStore Events { get; }

    public TestInventory Inventory { get; } = new();

    public AgentRuntime Runtime { get; }

    public Guid ComputerId => Config.Load().ComputerId ?? Guid.Empty;

    public Task<TimeSpan> StepAsync() => Runtime.RunOnceAsync(CancellationToken.None);

    /// <summary>Runs heartbeats until the condition holds, advancing the shared clock between steps.</summary>
    public async Task RunUntilAsync(Func<bool> condition, int maxSteps = 10)
    {
        for (var i = 0; i < maxSteps && !condition(); i++)
        {
            await StepAsync();
            _server.Clock.Advance(TimeSpan.FromSeconds(61));
        }

        Assert.True(condition(), "Condition not reached.");
    }

    public void Dispose()
    {
        Runtime.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort.
        }
    }

    private AgentServerClient InMemoryClient(AgentConfig config)
    {
        HttpMessageHandler handler = _server.Server.CreateHandler();
        if (config is { State: AgentState.Enrolled, CertificatePem: { } pem })
        {
            handler = new CertificateHeaderHandler(X509Certificate2.CreateFromPem(pem)) { InnerHandler = handler };
        }

        return new AgentServerClient(new HttpClient(handler) { BaseAddress = _server.Server.BaseAddress });
    }
}
