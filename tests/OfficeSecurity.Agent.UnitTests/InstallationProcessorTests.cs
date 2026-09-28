using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.UnitTests;

/// <summary>Serves one installation job and records what the agent reports back.</summary>
public sealed class FakeJobServer : HttpMessageHandler
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public FakeJobServer(byte[] installer, AgentJob? job = null)
    {
        Installer = installer;
        Job = job ?? new AgentJob(Guid.NewGuid(), "Contoso Viewer", "viewer.msi", Convert.ToHexStringLower(SHA256.HashData(installer)),
            installer.Length, InstallerTypes.Msi, null, "CN=Contoso Ltd", AllowUnsigned: false);
    }

    public AgentJob Job { get; set; }

    /// <summary>What the package download returns (defaults to the approved installer).</summary>
    public byte[] Installer { get; set; }

    public bool RefuseStart { get; set; }

    public AgentJobResult? Result { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        if (path == ApiRoutes.AgentJobs)
        {
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new List<AgentJob> { Job }, options: Json) };
        }

        if (path == ApiRoutes.AgentJobStart(Job.JobId))
        {
            return new HttpResponseMessage(RefuseStart ? HttpStatusCode.Conflict : HttpStatusCode.NoContent);
        }

        if (path == ApiRoutes.AgentJobPackage(Job.JobId))
        {
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Installer) };
        }

        if (path == ApiRoutes.AgentJobResult(Job.JobId))
        {
            Result = await request.Content!.ReadFromJsonAsync<AgentJobResult>(Json, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }

        throw new InvalidOperationException("Unexpected request " + path);
    }
}

public sealed class InstallationProcessorTests : IDisposable
{
    private static readonly byte[] Installer = [.. Enumerable.Range(0, 5000).Select(i => (byte)(i % 251))];

    private readonly TempDirectory _dir = new();
    private readonly AgentPaths _paths;
    private readonly PendingEventStore _events;
    private readonly StubVerifier _verifier = new();
    private readonly RecordingRunner _runner = new();

    public InstallationProcessorTests()
    {
        _paths = new AgentPaths(_dir.Path);
        _events = new PendingEventStore(_paths, new FakeTimeProvider(DateTimeOffset.UtcNow));
    }

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task Verified_installer_is_run_and_the_result_reported()
    {
        var server = new FakeJobServer(Installer);
        await ProcessAsync(server);

        var run = Assert.Single(_runner.Runs);
        Assert.Equal(Installer, run);
        Assert.Equal(JobStatuses.Succeeded, server.Result!.Status);
        Assert.Empty(Directory.GetFiles(Path.Combine(_paths.DataDirectory, "installers")));
    }

    [Fact]
    public async Task Installer_with_a_different_fingerprint_is_never_run()
    {
        var tampered = (byte[])Installer.Clone();
        tampered[100] ^= 0xFF;
        var server = new FakeJobServer(Installer) { Installer = tampered };
        await ProcessAsync(server);

        Assert.Empty(_runner.Runs);
        Assert.Equal(JobStatuses.Failed, server.Result!.Status);
        Assert.Contains("SHA-256", server.Result.Message, StringComparison.Ordinal);
        var alert = Assert.Single(_events.PeekPending(10));
        Assert.Equal(EventSeverities.Critical, alert.Severity);
    }

    [Fact]
    public async Task Installer_of_the_wrong_size_is_never_run()
    {
        var server = new FakeJobServer(Installer) { Installer = Installer[..4000] };
        await ProcessAsync(server);

        Assert.Empty(_runner.Runs);
        Assert.Equal(JobStatuses.Failed, server.Result!.Status);
    }

    [Fact]
    public async Task Installer_larger_than_approved_is_refused_while_downloading()
    {
        var server = new FakeJobServer(Installer) { Installer = [.. Installer, .. Installer] };
        await ProcessAsync(server);

        Assert.Empty(_runner.Runs);
        Assert.Equal(JobStatuses.Failed, server.Result!.Status);
    }

    [Fact]
    public async Task Installer_signed_by_another_publisher_is_never_run()
    {
        _verifier.Result = new SignatureCheck(SignatureState.Valid, "CN=Someone Else", null);
        var server = new FakeJobServer(Installer);
        await ProcessAsync(server);

        Assert.Empty(_runner.Runs);
        Assert.Contains("Someone Else", server.Result!.Message, StringComparison.Ordinal);
        Assert.Equal(EventSeverities.Critical, Assert.Single(_events.PeekPending(10)).Severity);
    }

    [Theory]
    [InlineData(SignatureState.NotSigned)]
    [InlineData(SignatureState.Invalid)]
    [InlineData(SignatureState.Unavailable)]
    public async Task Unsigned_or_broken_installer_is_refused_unless_unsigned_was_allowed(SignatureState state)
    {
        _verifier.Result = new SignatureCheck(state, null, state == SignatureState.Invalid ? "signature broken" : null);
        var server = new FakeJobServer(Installer);
        await ProcessAsync(server);

        Assert.Empty(_runner.Runs);
        Assert.Equal(JobStatuses.Failed, server.Result!.Status);
    }

    [Theory]
    [InlineData(SignatureState.NotSigned, true)]
    [InlineData(SignatureState.Unavailable, true)]
    [InlineData(SignatureState.Invalid, false)]
    public async Task Allowing_unsigned_never_allows_a_broken_signature(SignatureState state, bool expectedToRun)
    {
        _verifier.Result = new SignatureCheck(state, null, null);
        var server = new FakeJobServer(Installer);
        server.Job = server.Job with { SignerSubject = null, AllowUnsigned = true };
        await ProcessAsync(server);

        Assert.Equal(expectedToRun ? 1 : 0, _runner.Runs.Count);
    }

    [Fact]
    public async Task Job_refused_by_the_server_is_not_downloaded_or_run()
    {
        var server = new FakeJobServer(Installer) { RefuseStart = true };
        await ProcessAsync(server);

        Assert.Empty(_runner.Runs);
        Assert.Null(server.Result);
    }

    [Fact]
    public async Task Server_supplied_file_name_cannot_escape_the_installers_folder()
    {
        var server = new FakeJobServer(Installer);
        server.Job = server.Job with { FileName = @"..\..\Windows\System32\evil.msi" };
        await ProcessAsync(server);

        Assert.StartsWith(Path.Combine(_paths.DataDirectory, "installers"), _runner.Paths.Single(), StringComparison.Ordinal);
    }

    private async Task ProcessAsync(FakeJobServer server)
    {
        using var client = new AgentServerClient(new HttpClient(server) { BaseAddress = new Uri("https://server.test:5443") });
        var processor = new InstallationProcessor(_paths, _verifier, _runner, _events, NullLogger.Instance);
        await processor.ProcessAsync(client, CancellationToken.None);
    }

    private sealed class StubVerifier : IInstallerVerifier
    {
        public SignatureCheck Result { get; set; } = new(SignatureState.Valid, "CN=Contoso Ltd", null);

        public SignatureCheck Check(string path) => Result;
    }

    private sealed class RecordingRunner : IInstallerRunner
    {
        public List<byte[]> Runs { get; } = [];

        public List<string> Paths { get; } = [];

        public Task<InstallerOutcome> RunAsync(AgentJob job, string installerPath, CancellationToken cancellationToken)
        {
            Runs.Add(File.ReadAllBytes(installerPath));
            Paths.Add(installerPath);
            return Task.FromResult(new InstallerOutcome(JobStatuses.Succeeded, 0, "Installed successfully."));
        }
    }
}
