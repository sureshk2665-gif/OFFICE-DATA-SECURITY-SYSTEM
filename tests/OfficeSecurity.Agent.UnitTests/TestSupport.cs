using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

/// <summary>Skips the test unless it runs on Windows (and, optionally, with administrator rights).</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute(bool requiresAdministrator = false)
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows only.";
        }
        else if (requiresAdministrator && !IsAdministrator())
        {
            Skip = "Requires administrator rights.";
        }
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}

public sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ocss-agent-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            // Best effort.
        }
    }
}

/// <summary>A scripted stand-in for the server's agent endpoints.</summary>
public sealed class FakeAgentServer : HttpMessageHandler
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public ECDsa TrustedKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public Guid ComputerId { get; } = Guid.NewGuid();

    public long LatestVersion { get; set; } = 1;

    /// <summary>Builds what GET /agent/policy returns; defaults to a correctly signed policy at LatestVersion.</summary>
    public Func<SignedPolicyEnvelope>? PolicyOverride { get; set; }

    public bool Offline { get; set; }

    public HttpStatusCode? FailWith { get; set; }

    public int PolicyRequests { get; private set; }

    public int InventoryReports { get; private set; }

    public List<AgentEvent> Events { get; } = [];

    public string TrustedKeyBase64 => Convert.ToBase64String(TrustedKey.ExportSubjectPublicKeyInfo());

    /// <summary>The settings in the policies this server signs.</summary>
    public PolicySettings Settings { get; set; } = new();

    public IReadOnlyList<PolicyExemption> Exemptions { get; set; } = [];

    public SignedPolicyEnvelope Sign(long version, ECDsa? key = null, Guid? computerId = null) =>
        new PolicySigner(key ?? TrustedKey).Sign(Settings.ToDocument(computerId ?? ComputerId, version, DateTimeOffset.UtcNow, Exemptions));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Offline)
        {
            throw new HttpRequestException("simulated network failure");
        }

        if (FailWith is { } status)
        {
            return new HttpResponseMessage(status);
        }

        var path = request.RequestUri!.AbsolutePath;
        object? body = path switch
        {
            ApiRoutes.AgentHeartbeat => new AgentHeartbeatResponse(LatestVersion, 60),
            ApiRoutes.AgentPolicy => Policy(),
            ApiRoutes.AgentEvents => await RecordEventsAsync(request, cancellationToken),
            ApiRoutes.AgentInventory => await CountInventoryAsync(request, cancellationToken),
            ApiRoutes.AgentLoginTicket => new ComputerLoginTicketResponse("ticket-123", DateTimeOffset.UtcNow.AddMinutes(2)),
            _ => throw new InvalidOperationException("Unexpected request " + path),
        };
        return body is null ? new HttpResponseMessage(HttpStatusCode.NoContent) : new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(body, body.GetType(), options: Json) };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            TrustedKey.Dispose();
        }

        base.Dispose(disposing);
    }

    private SignedPolicyEnvelope Policy()
    {
        PolicyRequests++;
        return PolicyOverride?.Invoke() ?? Sign(LatestVersion);
    }

    public List<AgentInventoryRequest> InventoryRequests { get; } = [];

    private async Task<object?> CountInventoryAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        InventoryReports++;
        InventoryRequests.Add((await request.Content!.ReadFromJsonAsync<AgentInventoryRequest>(Json, cancellationToken))!);
        return null;
    }

    private async Task<object> RecordEventsAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var payload = await request.Content!.ReadFromJsonAsync<AgentEventsRequest>(Json, cancellationToken);
        Events.AddRange(payload!.Events);
        return new AgentEventsResponse(payload.Events.Count);
    }
}

public sealed class FakeInventory : IInventoryCollector
{
    public List<ConnectedDevice> Devices { get; } = [];

    public HardwareInventory CollectHardware() => new("TEST-PC", "Windows 11 Pro", "24H2", "26100.1", "Professional", "Contoso", "Model 1", "SN1", "CPU", 16384, 256, true, false, "WORKGROUP");

    public IReadOnlyList<ConnectedDevice> CollectDevices() => [.. Devices];

    public List<InstalledSoftware> Software { get; } = [];

    public IReadOnlyList<InstalledSoftware> CollectSoftware() => [.. Software];

    public List<RecoveryKeyReport> RecoveryKeys { get; } = [];

    public IReadOnlyList<RecoveryKeyReport> CollectRecoveryKeys() => [.. RecoveryKeys];
}

/// <summary>An agent runtime wired to a fake server, with its own data folder and clock.</summary>
public sealed class AgentHarness : IDisposable
{
    private readonly TempDirectory _dir = new();

    public AgentHarness(FakeAgentServer server, FakeTimeProvider? clock = null)
    {
        Server = server;
        Clock = clock ?? new FakeTimeProvider(DateTimeOffset.UtcNow);
        Paths = new AgentPaths(_dir.Path);
        ConfigStore = new AgentConfigStore(Paths, protectDirectory: false);
        ConfigStore.Save(new AgentConfig
        {
            State = AgentState.Enrolled,
            ServerAddress = "https://server.test:5443",
            ComputerId = server.ComputerId,
            PolicySigningPublicKey = server.TrustedKeyBase64,
            KeyName = "test-key",
        });
        Events = new PendingEventStore(Paths, Clock);
        PolicyCache = new PolicyCache(Paths);
        Runtime = CreateRuntime();
    }

    public FakeAgentServer Server { get; }

    public FakeTimeProvider Clock { get; }

    public AgentPaths Paths { get; }

    public AgentConfigStore ConfigStore { get; }

    public PendingEventStore Events { get; }

    public PolicyCache PolicyCache { get; }

    public FakeInventory Inventory { get; } = new();

    /// <summary>Security controls the runtime enforces (none by default).</summary>
    public List<IEnforcer> Enforcers { get; } = [];

    public AgentRuntime Runtime { get; private set; }

    /// <summary>Simulates a service restart: a new runtime over the same data folder.</summary>
    public void Restart()
    {
        Runtime.Dispose();
        Runtime = CreateRuntime();
    }

    public void Dispose()
    {
        Runtime.Dispose();
        _dir.Dispose();
    }

    private AgentRuntime CreateRuntime() => new(
        ConfigStore,
        new FileDeviceKeyStore(Paths.FileKeyDirectory),
        Inventory,
        new EnforcementCoordinator(Enforcers, Clock),
        Events,
        PolicyCache,
        Clock,
        NullLogger<AgentRuntime>.Instance,
        new AgentRuntimeOptions { AgentVersion = "test" },
        _ => new AgentServerClient(new HttpClient(Server, disposeHandler: false) { BaseAddress = new Uri("https://server.test:5443") }));
}
