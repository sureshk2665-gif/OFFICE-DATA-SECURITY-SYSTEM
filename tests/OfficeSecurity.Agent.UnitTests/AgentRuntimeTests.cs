using System.Security.Cryptography;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

public sealed class AgentRuntimeTests
{
    [Fact]
    public async Task Valid_policy_is_applied_cached_and_enforced_after_restart_while_offline()
    {
        using var server = new FakeAgentServer { LatestVersion = 3 };
        using var agent = new AgentHarness(server);

        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.Equal(3, agent.Runtime.CurrentPolicy.Version);
        Assert.Equal(Enum.GetValues<SecurityControl>().Length, agent.Runtime.Controls.Count);

        server.Offline = true;
        agent.Restart();
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Equal(3, agent.Runtime.CurrentPolicy.Version);
    }

    [Fact]
    public async Task Policy_signed_with_another_key_is_rejected_and_reported()
    {
        using var server = new FakeAgentServer { LatestVersion = 2 };
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        server.PolicyOverride = () => server.Sign(2, attacker);
        using var agent = new AgentHarness(server);

        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Equal(0, agent.Runtime.CurrentPolicy.Version);
        Assert.Contains(server.Events, e => e.Type == SecurityEventType.PolicyTamperAttempt && e.Severity == EventSeverities.Critical);

        // The same bad version is not downloaded again on every heartbeat.
        agent.Clock.Advance(TimeSpan.FromMinutes(2));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.Equal(1, server.PolicyRequests);
    }

    [Fact]
    public async Task Policy_for_another_computer_or_older_version_is_rejected()
    {
        using var server = new FakeAgentServer { LatestVersion = 5 };
        using var agent = new AgentHarness(server);
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.Equal(5, agent.Runtime.CurrentPolicy.Version);

        server.LatestVersion = 6;
        server.PolicyOverride = () => server.Sign(6, computerId: Guid.NewGuid());
        agent.Clock.Advance(TimeSpan.FromMinutes(2));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.Equal(5, agent.Runtime.CurrentPolicy.Version);

        server.LatestVersion = 7;
        server.PolicyOverride = () => server.Sign(4);
        agent.Clock.Advance(TimeSpan.FromMinutes(2));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.Equal(5, agent.Runtime.CurrentPolicy.Version);
        Assert.Equal(2, server.Events.Count(e => e.Type == SecurityEventType.PolicyTamperAttempt));
    }

    [Fact]
    public async Task Tampered_policy_file_is_rejected_at_start_up()
    {
        using var server = new FakeAgentServer { LatestVersion = 2 };
        using var agent = new AgentHarness(server);
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        // Someone edits the cached policy to switch protection off.
        var text = await File.ReadAllTextAsync(agent.Paths.PolicyCacheFile);
        var edited = text.Replace("\"Payload\":\"", "\"Payload\":\"AAAA", StringComparison.Ordinal);
        await File.WriteAllTextAsync(agent.Paths.PolicyCacheFile, edited);

        server.Offline = true;
        agent.Restart();
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Equal(0, agent.Runtime.CurrentPolicy.Version);
        Assert.False(File.Exists(agent.Paths.PolicyCacheFile));
        Assert.Contains(agent.Events.PeekPending(100), e => e.Type == SecurityEventType.PolicyTamperAttempt);
    }

    [Fact]
    public async Task Events_are_kept_while_offline_and_uploaded_when_the_server_returns()
    {
        using var server = new FakeAgentServer { Offline = true };
        using var agent = new AgentHarness(server);

        var delay = await agent.Runtime.RunOnceAsync(CancellationToken.None);
        agent.Inventory.Devices.Add(new ConnectedDevice(@"USBSTOR\DISK&VEN_TEST\1", "Test USB Drive", "DiskDrive", "Test"));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.True(delay >= TimeSpan.FromSeconds(15));
        Assert.True(agent.Events.PendingCount() >= 1);
        Assert.Empty(server.Events);

        server.Offline = false;
        agent.Clock.Advance(TimeSpan.FromMinutes(5));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Contains(server.Events, e => e.Type == SecurityEventType.AgentStarted);
        Assert.Equal(0, agent.Events.PendingCount());
    }

    [Fact]
    public async Task Newly_connected_and_removed_devices_are_logged()
    {
        using var server = new FakeAgentServer();
        using var agent = new AgentHarness(server);
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        agent.Inventory.Devices.Add(new ConnectedDevice(@"USBSTOR\DISK&VEN_KINGSTON\123", "Kingston DataTraveler", "DiskDrive", "Kingston"));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        agent.Inventory.Devices.Clear();
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Contains(server.Events, e => e.Type == SecurityEventType.DeviceConnected && e.Details!.Contains("Kingston DataTraveler", StringComparison.Ordinal));
        Assert.Contains(server.Events, e => e.Type == SecurityEventType.DeviceDisconnected);
        Assert.True(server.InventoryReports >= 2);
    }

    [Fact]
    public async Task Rejected_certificate_marks_the_agent_retired_but_keeps_the_policy()
    {
        using var server = new FakeAgentServer { LatestVersion = 4 };
        using var agent = new AgentHarness(server);
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        server.FailWith = System.Net.HttpStatusCode.Unauthorized;
        agent.Clock.Advance(TimeSpan.FromMinutes(2));
        var delay = await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Equal(AgentState.Retired, agent.ConfigStore.Load().State);
        Assert.Equal(4, agent.Runtime.CurrentPolicy.Version);
        Assert.Equal(TimeSpan.FromHours(1), delay);
    }

    [Fact]
    public async Task Local_pipe_requests_expose_status_and_tickets_only()
    {
        using var server = new FakeAgentServer();
        using var agent = new AgentHarness(server);
        var local = new AgentLocalServer(agent.Runtime, Microsoft.Extensions.Logging.Abstractions.NullLogger<AgentLocalServer>.Instance, "test-" + Guid.NewGuid().ToString("N"));

        var status = await local.ProcessAsync(new AgentLocalRequest(AgentLocalProtocol.StatusCommand), CancellationToken.None);
        var ticket = await local.ProcessAsync(new AgentLocalRequest(AgentLocalProtocol.LoginTicketCommand), CancellationToken.None);
        var unknown = await local.ProcessAsync(new AgentLocalRequest("disable-protection"), CancellationToken.None);

        Assert.Equal(nameof(AgentState.Enrolled), status.Status!.State);
        Assert.Equal(server.ComputerId, status.Status.ComputerId);
        Assert.Equal("ticket-123", ticket.LoginTicket);
        Assert.False(unknown.Success);
    }

    [Fact]
    public async Task Local_pipe_round_trip_works()
    {
        using var server = new FakeAgentServer();
        using var agent = new AgentHarness(server);
        var pipeName = "ocss-test-" + Guid.NewGuid().ToString("N")[..12];
        var local = new AgentLocalServer(agent.Runtime, Microsoft.Extensions.Logging.Abstractions.NullLogger<AgentLocalServer>.Instance, pipeName);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serving = local.RunAsync(cts.Token);

        // Server identity verification is Windows-specific and requires the installed agent; off here.
        var status = await Client.Core.AgentLocalClient.TryGetStatusAsync(pipeName, verifyServer: false, cts.Token);

        await cts.CancelAsync();
        await serving;
        Assert.Equal(nameof(AgentState.Enrolled), status!.State);
    }

    [WindowsFact]
    public async Task On_Windows_a_pipe_not_served_by_the_installed_agent_is_not_trusted()
    {
        using var server = new FakeAgentServer();
        using var agent = new AgentHarness(server);
        var pipeName = "ocss-test-" + Guid.NewGuid().ToString("N")[..12];
        var local = new AgentLocalServer(agent.Runtime, Microsoft.Extensions.Logging.Abstractions.NullLogger<AgentLocalServer>.Instance, pipeName);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serving = local.RunAsync(cts.Token);

        // This test process is not the installed agent, so the staff application must refuse to trust it.
        var status = await Client.Core.AgentLocalClient.TryGetStatusAsync(pipeName, verifyServer: true, cts.Token);

        await cts.CancelAsync();
        await serving;
        Assert.Null(status);
    }
}
