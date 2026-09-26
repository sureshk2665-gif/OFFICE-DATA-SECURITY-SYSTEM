using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class ComputerLifecycleTests
{
    private static async Task<ComputerDetail> GetComputerAsync(HttpClient admin, Guid id) =>
        (await admin.GetFromJsonAsync<ComputerDetail>(ApiRoutes.ComputerById(id)))!;

    [Fact]
    public async Task Agent_enrolls_waits_for_approval_then_reports_and_applies_the_signed_policy()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner));

        await agent.StepAsync();
        Assert.Equal(AgentState.PendingApproval, agent.Config.Load().State);

        var pending = await admin.GetFromJsonAsync<PagedResult<ComputerSummary>>(ApiRoutes.Computers);
        var listed = Assert.Single(pending!.Items);
        Assert.Equal(ComputerStatuses.PendingApproval, listed.Status);
        Assert.Equal(agent.Inventory.ComputerName, listed.Hostname);
        Assert.False(listed.IsOnline);

        // Still waiting: nothing changes until an administrator approves.
        await agent.StepAsync();
        Assert.Equal(AgentState.PendingApproval, agent.Config.Load().State);

        (await admin.PostAsync(new Uri(ApiRoutes.ComputerApprove(agent.ComputerId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        await agent.StepAsync();
        Assert.Equal(AgentState.Enrolled, agent.Config.Load().State);

        await agent.StepAsync();
        Assert.Equal(1, agent.Runtime.CurrentPolicy.Version);

        var detail = await GetComputerAsync(admin, agent.ComputerId);
        Assert.True(detail.Summary.IsOnline);
        Assert.Equal(ComputerStatuses.Trusted, detail.Summary.Status);
        Assert.Equal("1.2.3-test", detail.Summary.AgentVersion);
        Assert.Equal("Microsoft Windows 11 Pro", detail.Hardware!.OsName);
        Assert.Equal(Enum.GetValues<SecurityControl>().Length, detail.Controls.Count);
        Assert.All(detail.Controls, c => Assert.Equal(ControlState.NotImplemented, c.State));

        // The agent reports version 1 as applied on its next heartbeat.
        server.Clock.Advance(TimeSpan.FromSeconds(61));
        await agent.StepAsync();
        detail = await GetComputerAsync(admin, agent.ComputerId);
        Assert.Equal(1, detail.Summary.AppliedPolicyVersion);
        Assert.Equal(1, detail.Summary.LatestPolicyVersion);

        var events = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?computerId={agent.ComputerId}");
        Assert.Contains(events!.Items, e => e.EventType == nameof(SecurityEventType.AgentStarted));
        Assert.Contains(events.Items, e => e.EventType == nameof(SecurityEventType.PolicyApplied));

        var overview = await admin.GetFromJsonAsync<DashboardOverviewResponse>(ApiRoutes.DashboardOverview);
        Assert.Equal(1, overview!.ComputersTrusted);
        Assert.Equal(1, overview.ComputersOnline);
    }

    [Fact]
    public async Task Policy_changes_reach_the_agent_with_a_higher_version()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await EnrolledAgentAsync(server, owner, admin);

        var policies = await admin.GetFromJsonAsync<List<PolicySummary>>(ApiRoutes.Policies);
        var defaultPolicy = Assert.Single(policies!, p => p.IsDefault);
        var detail = await admin.GetFromJsonAsync<PolicyDetail>(ApiRoutes.PolicyById(defaultPolicy.Id));
        var changed = detail!.Settings with
        {
            RemovableStorage = new RemovableStorageSettings { Mode = EnforcementMode.Audit },
            Agent = new AgentSettings { HeartbeatIntervalSeconds = 30 },
        };
        (await admin.PutAsJsonAsync(ApiRoutes.PolicyById(defaultPolicy.Id), new SavePolicyRequest(detail.Name, detail.Description, changed))).EnsureSuccessStatusCode();

        await agent.RunUntilAsync(() => agent.Runtime.CurrentPolicy.Version == 2);
        Assert.Equal(EnforcementMode.Audit, agent.Runtime.CurrentPolicy.RemovableStorage.Mode);

        // Assigning a different policy also produces a new, higher version.
        var strict = await (await admin.PostAsJsonAsync(ApiRoutes.Policies, new SavePolicyRequest("Accounts department", null,
            new PolicySettings { Bluetooth = new BluetoothSettings { Mode = BluetoothMode.DisableRadio } })))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<PolicyDetail>();
        (await admin.PutAsJsonAsync(ApiRoutes.ComputerPolicy(agent.ComputerId), new AssignPolicyRequest(strict!.Id))).EnsureSuccessStatusCode();

        await agent.RunUntilAsync(() => agent.Runtime.CurrentPolicy.Version == 3);
        Assert.Equal(BluetoothMode.DisableRadio, agent.Runtime.CurrentPolicy.Bluetooth.Mode);
        Assert.Equal("Accounts department", (await GetComputerAsync(admin, agent.ComputerId)).Summary.PolicyName);
    }

    [Fact]
    public async Task Devices_and_connection_events_are_reported()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await EnrolledAgentAsync(server, owner, admin);

        agent.Inventory.Devices.Add(new ConnectedDevice(@"USBSTOR\DISK&VEN_KINGSTON&PROD_DT\0019E06B", "Kingston DataTraveler 3.0 USB Device", "DiskDrive", "Kingston"));
        await agent.StepAsync();

        var detail = await GetComputerAsync(admin, agent.ComputerId);
        var device = Assert.Single(detail.Devices);
        Assert.True(device.IsConnected);
        Assert.Equal("DiskDrive", device.DeviceClass);

        agent.Inventory.Devices.Clear();
        await agent.StepAsync();
        Assert.False(Assert.Single((await GetComputerAsync(admin, agent.ComputerId)).Devices).IsConnected);

        var events = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?search=Kingston");
        Assert.Contains(events!.Items, e => e.EventType == nameof(SecurityEventType.DeviceConnected));
        Assert.Contains(events.Items, e => e.EventType == nameof(SecurityEventType.DeviceDisconnected));
    }

    [Fact]
    public async Task Invalid_and_reused_enrollment_codes_are_refused()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var code = await server.CreateEnrollmentCodeAsync(owner);

        using var bad = new AgentHarness(server, "AAAA-BBBB-CCCC");
        await bad.StepAsync();
        Assert.Equal(AgentState.EnrollmentFailed, bad.Config.Load().State);

        using var first = new AgentHarness(server, code);
        await first.StepAsync();
        Assert.Equal(AgentState.PendingApproval, first.Config.Load().State);

        using var second = new AgentHarness(server, code);
        await second.StepAsync();
        Assert.Equal(AgentState.EnrollmentFailed, second.Config.Load().State);
    }

    [Fact]
    public async Task Rejected_computer_is_told_so_and_cannot_use_agent_endpoints()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner));
        await agent.StepAsync();

        (await admin.PostAsync(new Uri(ApiRoutes.ComputerReject(agent.ComputerId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        await agent.StepAsync();

        Assert.Equal(AgentState.Rejected, agent.Config.Load().State);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync(new Uri(ApiRoutes.ComputerApprove(agent.ComputerId), UriKind.Relative), null)).StatusCode);
    }

    [Fact]
    public async Task Retired_computer_is_no_longer_accepted_but_keeps_its_last_policy()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await EnrolledAgentAsync(server, owner, admin);

        (await admin.PostAsync(new Uri(ApiRoutes.ComputerRetire(agent.ComputerId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        server.Clock.Advance(TimeSpan.FromSeconds(61));
        await agent.StepAsync();

        Assert.Equal(AgentState.Retired, agent.Config.Load().State);
        Assert.Equal(1, agent.Runtime.CurrentPolicy.Version);
        var list = await admin.GetFromJsonAsync<PagedResult<ComputerSummary>>(ApiRoutes.Computers);
        Assert.Empty(list!.Items);
    }

    [Fact]
    public async Task Certificates_not_issued_by_this_server_are_refused()
    {
        await using var server = new ServerFactory();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var foreign = new CertificateRequest("CN=" + Guid.NewGuid(), key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var client = new HttpClient(new CertificateHeaderHandler(foreign) { InnerHandler = server.Server.CreateHandler() }) { BaseAddress = server.Server.BaseAddress };

        var response = await client.PostAsJsonAsync(ApiRoutes.AgentHeartbeat, new AgentHeartbeatRequest("x", 0, [], 0));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Staff_restricted_to_a_computer_can_sign_in_only_with_that_computers_ticket()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var pcA = await EnrolledAgentAsync(server, owner, admin);
        using var pcB = await EnrolledAgentAsync(server, owner, admin);
        var (staffId, _) = await server.CreateActiveStaffAsync(owner, "EMP700", "Staff member pass 2026");
        using var anonymous = server.Client();

        // Before any assignment the account is not restricted.
        Assert.Equal(HttpStatusCode.OK, (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP700", "Staff member pass 2026"))).StatusCode);

        (await admin.PutAsJsonAsync(ApiRoutes.ComputerStaff(pcA.ComputerId), new AssignStaffRequest([staffId]))).EnsureSuccessStatusCode();

        var noTicket = await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP700", "Staff member pass 2026"));
        Assert.Equal(HttpStatusCode.Forbidden, noTicket.StatusCode);

        var wrongComputer = await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin,
            new StaffLoginRequest("EMP700", "Staff member pass 2026", await pcB.Runtime.GetLoginTicketAsync(CancellationToken.None)));
        Assert.Equal(HttpStatusCode.Forbidden, wrongComputer.StatusCode);

        var ticket = await pcA.Runtime.GetLoginTicketAsync(CancellationToken.None);
        Assert.Equal(HttpStatusCode.OK, (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP700", "Staff member pass 2026", ticket))).StatusCode);

        // A ticket works only once.
        Assert.Equal(HttpStatusCode.Forbidden, (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP700", "Staff member pass 2026", ticket))).StatusCode);

        var detail = await GetComputerAsync(admin, pcA.ComputerId);
        Assert.Equal("EMP700", Assert.Single(detail.AssignedStaff).EmployeeCode);
    }

    [Fact]
    public async Task Policy_management_rules_are_enforced()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor9", AdminRoles.Auditor);
        using var auditor = server.Client(auditorToken);

        var defaultPolicy = Assert.Single((await admin.GetFromJsonAsync<List<PolicySummary>>(ApiRoutes.Policies))!, p => p.IsDefault);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync(new Uri(ApiRoutes.PolicyById(defaultPolicy.Id), UriKind.Relative))).StatusCode);

        var invalid = new PolicySettings { Agent = new AgentSettings { HeartbeatIntervalSeconds = 1 } };
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(ApiRoutes.Policies, new SavePolicyRequest("Bad", null, invalid))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync(ApiRoutes.Policies, new SavePolicyRequest(defaultPolicy.Name, null, new PolicySettings()))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsJsonAsync(ApiRoutes.Policies, new SavePolicyRequest("Auditor policy", null, new PolicySettings()))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(new Uri(ApiRoutes.Policies, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsync(new Uri(ApiRoutes.EnrollmentCodes, UriKind.Relative), null)).StatusCode);
    }

    [Fact]
    public async Task Duplicate_event_uploads_are_stored_once()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await EnrolledAgentAsync(server, owner, admin);
        var pem = agent.Config.Load().CertificatePem!;
        using var client = new HttpClient(new CertificateHeaderHandler(X509Certificate2.CreateFromPem(pem)) { InnerHandler = server.Server.CreateHandler() }) { BaseAddress = server.Server.BaseAddress };
        var evt = new AgentEvent(Guid.NewGuid(), SecurityEventType.DeviceConnected, EventSeverities.Information, server.Clock.GetUtcNow(), "duplicate-check");

        var first = await (await client.PostAsJsonAsync(ApiRoutes.AgentEvents, new AgentEventsRequest([evt, evt]))).Content.ReadFromJsonAsync<AgentEventsResponse>();
        var retry = await (await client.PostAsJsonAsync(ApiRoutes.AgentEvents, new AgentEventsRequest([evt]))).Content.ReadFromJsonAsync<AgentEventsResponse>();

        Assert.Equal(1, first!.Accepted);
        Assert.Equal(0, retry!.Accepted);
        var stored = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?search=duplicate-check");
        Assert.Single(stored!.Items);
    }

    internal static async Task<AgentHarness> EnrolledAgentAsync(ServerFactory server, string owner, HttpClient admin, bool useRealTls = false)
    {
        var agent = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner), useRealTls);
        await agent.StepAsync();
        (await admin.PostAsync(new Uri(ApiRoutes.ComputerApprove(agent.ComputerId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        await agent.StepAsync();
        await agent.StepAsync();
        Assert.Equal(AgentState.Enrolled, agent.Config.Load().State);
        return agent;
    }
}
