using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.Sqlite;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class AlertTests
{
    internal static HttpClient AgentClient(ServerFactory server, AgentHarness agent) =>
        new(new CertificateHeaderHandler(X509Certificate2.CreateFromPem(agent.Config.Load().CertificatePem!)) { InnerHandler = server.Server.CreateHandler() })
        {
            BaseAddress = server.Server.BaseAddress,
        };

    internal static async Task SendAsync(HttpClient computer, ServerFactory server, params (SecurityEventType Type, string Severity, string Details)[] events) =>
        (await computer.PostAsJsonAsync(ApiRoutes.AgentEvents, new AgentEventsRequest(
            events.Select(e => new AgentEvent(Guid.NewGuid(), e.Type, e.Severity, server.Clock.GetUtcNow(), e.Details)).ToList()))).EnsureSuccessStatusCode();

    private static async Task<List<AlertResponse>> AlertsAsync(HttpClient admin, string status = AlertStatuses.Active) =>
        (await admin.GetFromJsonAsync<PagedResult<AlertResponse>>($"{ApiRoutes.Alerts}?status={status}&pageSize=200"))!.Items.ToList();

    private static async Task<(ServerFactory Server, string Owner, HttpClient Admin, AgentHarness Agent, HttpClient Computer)> SetUpAsync()
    {
        var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var admin = server.Client(owner);
        var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        await server.RunAlertEngineAsync(); // first run: start from the events that arrive from now on
        return (server, owner, admin, agent, AgentClient(server, agent));
    }

    [Fact]
    public async Task Events_raise_alerts_and_repeats_are_added_to_the_open_alert()
    {
        var (server, _, admin, agent, computer) = await SetUpAsync();
        await using var _ = server;
        using var a = admin;
        using var b = agent;
        using var c = computer;

        await SendAsync(computer, server,
            (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "USB drive blocking: settings changed and restored."),
            (SecurityEventType.UnauthorizedApplicationBlocked, EventSeverities.Information, "Audit mode — would be blocked by Application Control: C:\\x.exe"),
            (SecurityEventType.RemovableStorageBlocked, EventSeverities.Warning, "USB drive blocked: Kingston"));
        Assert.Equal(2, await server.RunAlertEngineAsync());

        var alerts = await AlertsAsync(admin);
        var tamper = Assert.Single(alerts, x => x.RuleCode == "tamper");
        Assert.Equal(EventSeverities.Critical, tamper.Severity);
        Assert.Equal(agent.Inventory.ComputerName, tamper.ComputerName, ignoreCase: true);
        Assert.Contains(alerts, x => x.RuleCode == "usb-blocked");
        Assert.DoesNotContain(alerts, x => x.RuleCode == "program-blocked"); // audit-mode reports do not alert

        // The same problem again: added to the open alert.
        await SendAsync(computer, server, (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "Again"),
            (SecurityEventType.UnauthorizedApplicationBlocked, EventSeverities.Warning, "Blocked by Application Control: C:\\x.exe"));
        Assert.Equal(1, await server.RunAlertEngineAsync());
        alerts = await AlertsAsync(admin);
        tamper = Assert.Single(alerts, x => x.RuleCode == "tamper");
        Assert.Equal(2, tamper.EventCount);
        Assert.Equal("Again", tamper.Details);
        Assert.Contains(alerts, x => x.RuleCode == "program-blocked");

        // Nothing new: nothing changes.
        Assert.Equal(0, await server.RunAlertEngineAsync());

        var summary = await admin.GetFromJsonAsync<AlertSummaryResponse>(ApiRoutes.AlertSummary);
        Assert.Equal(3, summary!.Open);
        Assert.Equal(1, summary.OpenCritical);
        var overview = await admin.GetFromJsonAsync<DashboardOverviewResponse>(ApiRoutes.DashboardOverview);
        Assert.Equal(3, overview!.OpenAlerts);
        Assert.Equal(1, overview.OpenCriticalAlerts);
    }

    [Fact]
    public async Task Events_from_before_the_first_run_do_not_flood_a_new_installation_with_alerts()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        using var computer = AgentClient(server, agent);
        await SendAsync(computer, server, (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "old"));

        Assert.Equal(0, await server.RunAlertEngineAsync());
        Assert.DoesNotContain(await AlertsAsync(admin), x => x.RuleCode == "tamper");
    }

    [Fact]
    public async Task Failed_windows_sign_ins_alert_only_at_the_threshold_and_resolved_ones_are_not_counted_again()
    {
        var (server, _, admin, agent, computer) = await SetUpAsync();
        await using var _ = server;
        using var a = admin;
        using var b = agent;
        using var c = computer;
        var failure = (SecurityEventType.FailedLogin, EventSeverities.Warning, "Failed Windows sign-in for PC\\anna (at the computer): wrong password.");

        await SendAsync(computer, server, failure, failure, failure, failure);
        await server.RunAlertEngineAsync();
        Assert.DoesNotContain(await AlertsAsync(admin), x => x.RuleCode == "windows-failed-sign-ins");

        await SendAsync(computer, server, failure);
        await server.RunAlertEngineAsync();
        var alert = Assert.Single(await AlertsAsync(admin), x => x.RuleCode == "windows-failed-sign-ins");
        Assert.Equal(5, alert.EventCount);

        (await admin.PostAsJsonAsync(ApiRoutes.AlertResolve(alert.Id), new ResolveAlertRequest("Anna forgot her password"))).EnsureSuccessStatusCode();
        await SendAsync(computer, server, failure);
        await server.RunAlertEngineAsync();
        Assert.DoesNotContain(await AlertsAsync(admin), x => x.RuleCode == "windows-failed-sign-ins");

        // Outside the window, old failures do not count.
        server.Clock.Advance(TimeSpan.FromMinutes(20));
        await SendAsync(computer, server, failure, failure, failure, failure);
        await server.RunAlertEngineAsync();
        Assert.DoesNotContain(await AlertsAsync(admin), x => x.RuleCode == "windows-failed-sign-ins");
    }

    [Fact]
    public async Task A_stopped_agent_alerts_but_a_normal_windows_shutdown_does_not()
    {
        var (server, _, admin, agent, computer) = await SetUpAsync();
        await using var _ = server;
        using var a = admin;
        using var b = agent;
        using var c = computer;

        // Windows shut down: the agent's notice, then silence for hours.
        await agent.Runtime.NotifyStoppingAsync(windowsShuttingDown: true, TimeSpan.FromSeconds(5));
        server.Clock.Advance(TimeSpan.FromHours(10));
        await server.RunAlertEngineAsync();
        using var nextMorning = await server.FreshOwnerClientAsync();
        Assert.Empty(await AlertsAsync(nextMorning));

        // Started again, then the service is stopped while Windows keeps running.
        await agent.StepAsync();
        await agent.Runtime.NotifyStoppingAsync(windowsShuttingDown: false, TimeSpan.FromSeconds(5));
        await server.RunAlertEngineAsync();
        var stopped = Assert.Single(await AlertsAsync(nextMorning));
        Assert.Equal("agent-stopped", stopped.RuleCode);
        Assert.Equal(EventSeverities.Critical, stopped.Severity);

        // It also stays silent: "not reporting" after the threshold (60 minutes by default).
        server.Clock.Advance(TimeSpan.FromMinutes(61));
        await server.RunAlertEngineAsync();
        using var later = await server.FreshOwnerClientAsync();
        Assert.Contains(await AlertsAsync(later), x => x.RuleCode == "computer-not-reporting");

        // Reporting again resolves that alert automatically.
        await agent.StepAsync();
        await server.RunAlertEngineAsync();
        Assert.DoesNotContain(await AlertsAsync(later), x => x.RuleCode == "computer-not-reporting");
        var resolved = Assert.Single(await AlertsAsync(later, AlertStatuses.Resolved), x => x.RuleCode == "computer-not-reporting");
        Assert.Equal("System", resolved.ResolvedBy);
    }

    [Fact]
    public async Task A_protection_that_fails_raises_an_alert_that_resolves_when_it_works_again()
    {
        var (server, _, admin, agent, computer) = await SetUpAsync();
        await using var _ = server;
        using var a = admin;
        using var b = agent;
        using var c = computer;
        var now = server.Clock.GetUtcNow();

        (await computer.PostAsJsonAsync(ApiRoutes.AgentHeartbeat, new AgentHeartbeatRequest("1.0", 1,
            [new ControlStatus(SecurityControl.DiskEncryption, ControlState.Failed, "NOT encrypted: C:", now)], 0))).EnsureSuccessStatusCode();
        await server.RunAlertEngineAsync();
        var alert = Assert.Single(await AlertsAsync(admin), x => x.RuleCode == "protection-failed");
        Assert.Contains("NOT encrypted: C:", alert.Details, StringComparison.Ordinal);

        (await computer.PostAsJsonAsync(ApiRoutes.AgentHeartbeat, new AgentHeartbeatRequest("1.0", 1,
            [new ControlStatus(SecurityControl.DiskEncryption, ControlState.Enforced, "C: protected", now)], 0))).EnsureSuccessStatusCode();
        await server.RunAlertEngineAsync();
        Assert.DoesNotContain(await AlertsAsync(admin), x => x.RuleCode == "protection-failed");
    }

    [Fact]
    public async Task Waiting_computers_repeated_failed_sign_ins_and_an_altered_audit_log_raise_alerts()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        await server.RunAlertEngineAsync();

        // A computer registers and waits for approval.
        using var agent = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner));
        await agent.StepAsync();
        await server.RunAlertEngineAsync();
        Assert.Contains(await AlertsAsync(admin), x => x.RuleCode == "computer-waiting");
        (await admin.PostAsync(new Uri(ApiRoutes.ComputerApprove(agent.ComputerId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        await server.RunAlertEngineAsync();
        Assert.DoesNotContain(await AlertsAsync(admin), x => x.RuleCode == "computer-waiting");

        // Five wrong passwords for one account name.
        using var anonymous = server.Client();
        for (var i = 0; i < 5; i++)
        {
            await anonymous.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest("mallory", "guess " + i));
        }

        await server.RunAlertEngineAsync();
        var signIns = Assert.Single(await AlertsAsync(admin), x => x.RuleCode == "system-failed-sign-ins");
        Assert.Contains("mallory", signIns.Title, StringComparison.Ordinal);
        Assert.Equal(5, signIns.EventCount);

        // Someone with access to the database file edits the audit log.
        await using (var connection = new SqliteConnection($"Data Source={server.DatabaseFile}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET ActorName = 'someone-else' WHERE Id = 2;";
            await command.ExecuteNonQueryAsync();
        }

        server.Clock.Advance(TimeSpan.FromHours(7)); // the integrity check runs every 6 hours
        await server.RunAlertEngineAsync();
        using (var later = await server.FreshOwnerClientAsync())
        {
            var integrity = Assert.Single(await AlertsAsync(later), x => x.RuleCode == "audit-integrity");
            Assert.Equal(EventSeverities.Critical, integrity.Severity);
        }

        server.Clock.Advance(TimeSpan.FromHours(7));
        await server.RunAlertEngineAsync();
        using var muchLater = await server.FreshOwnerClientAsync();
        Assert.Single(await AlertsAsync(muchLater, "All"), x => x.RuleCode == "audit-integrity"); // not raised twice
    }

    [Fact]
    public async Task Administrators_acknowledge_and_resolve_alerts_auditors_only_read_and_every_action_is_audited()
    {
        var (server, owner, admin, agent, computer) = await SetUpAsync();
        await using var _ = server;
        using var a = admin;
        using var b = agent;
        using var c = computer;
        await SendAsync(computer, server, (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "x"));
        await server.RunAlertEngineAsync();
        var alert = Assert.Single(await AlertsAsync(admin));

        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor5", AdminRoles.Auditor);
        using var auditor = server.Client(auditorToken);
        Assert.Single(await AlertsAsync(auditor));
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsync(new Uri(ApiRoutes.AlertAcknowledge(alert.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsJsonAsync(ApiRoutes.AlertResolve(alert.Id), new ResolveAlertRequest(null))).StatusCode);

        var acknowledged = await (await admin.PostAsync(new Uri(ApiRoutes.AlertAcknowledge(alert.Id), UriKind.Relative), null))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<AlertResponse>();
        Assert.Equal(AlertStatuses.Acknowledged, acknowledged!.Status);
        Assert.Equal("owner", acknowledged.AcknowledgedBy);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync(new Uri(ApiRoutes.AlertAcknowledge(alert.Id), UriKind.Relative), null)).StatusCode);

        // Repeats still count while acknowledged.
        await SendAsync(computer, server, (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "y"));
        await server.RunAlertEngineAsync();
        Assert.Equal(2, Assert.Single(await AlertsAsync(admin)).EventCount);

        var resolved = await (await admin.PostAsJsonAsync(ApiRoutes.AlertResolve(alert.Id), new ResolveAlertRequest("Checked with the user")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<AlertResponse>();
        Assert.Equal(AlertStatuses.Resolved, resolved!.Status);
        Assert.Equal("Checked with the user", resolved.ResolutionNote);
        Assert.Empty(await AlertsAsync(admin));

        // A new occurrence after resolving opens a new alert.
        await SendAsync(computer, server, (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "z"));
        await server.RunAlertEngineAsync();
        Assert.NotEqual(alert.Id, Assert.Single(await AlertsAsync(admin)).Id);

        var auditLog = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        Assert.Contains(auditLog!.Items, e => e.Action == "alert.acknowledge");
        Assert.Contains(auditLog.Items, e => e.Action == "alert.resolve" && e.Details!.Contains("Checked with the user", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Rules_can_be_changed_and_switched_off_with_validation()
    {
        var (server, owner, admin, agent, computer) = await SetUpAsync();
        await using var _ = server;
        using var a = admin;
        using var b = agent;
        using var c = computer;

        var rules = await admin.GetFromJsonAsync<List<AlertRuleResponse>>(ApiRoutes.AlertRules);
        Assert.Contains(rules!, r => r is { Code: "windows-failed-sign-ins", Threshold: 5, WindowMinutes: 15, UsesWindow: true });

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync(ApiRoutes.AlertRuleByCode("usb-blocked"), new UpdateAlertRuleRequest(true, "Loud", 1, 60))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync(ApiRoutes.AlertRuleByCode("windows-failed-sign-ins"), new UpdateAlertRuleRequest(true, "Warning", 0, 15))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PutAsJsonAsync(ApiRoutes.AlertRuleByCode("nope"), new UpdateAlertRuleRequest(true, "Warning", 1, 1))).StatusCode);

        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor6", AdminRoles.Auditor);
        using var auditor = server.Client(auditorToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PutAsJsonAsync(ApiRoutes.AlertRuleByCode("usb-blocked"), new UpdateAlertRuleRequest(false, "Warning", 1, 60))).StatusCode);

        var off = await (await admin.PutAsJsonAsync(ApiRoutes.AlertRuleByCode("usb-blocked"), new UpdateAlertRuleRequest(false, "Warning", 1, 60)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<AlertRuleResponse>();
        Assert.False(off!.Enabled);
        Assert.Equal("owner", off.UpdatedBy);
        (await admin.PutAsJsonAsync(ApiRoutes.AlertRuleByCode("tamper"), new UpdateAlertRuleRequest(true, "Warning", 1, 60))).EnsureSuccessStatusCode();

        await SendAsync(computer, server, (SecurityEventType.RemovableStorageBlocked, EventSeverities.Warning, "USB"),
            (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "x"));
        await server.RunAlertEngineAsync();
        var alerts = await AlertsAsync(admin);
        Assert.DoesNotContain(alerts, x => x.RuleCode == "usb-blocked");
        Assert.Equal(EventSeverities.Warning, Assert.Single(alerts, x => x.RuleCode == "tamper").Severity);

        var auditLog = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        Assert.Contains(auditLog!.Items, e => e.Action == "alert.rule.update" && e.TargetId == "usb-blocked");
    }
}
