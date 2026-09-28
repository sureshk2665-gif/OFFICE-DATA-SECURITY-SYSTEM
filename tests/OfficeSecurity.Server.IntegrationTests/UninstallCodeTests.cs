using System.Net;
using System.Net.Http.Json;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class UninstallCodeTests
{
    [Fact]
    public async Task Uninstall_codes_are_for_one_computer_expire_are_audited_and_only_administrators_get_them()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        var config = agent.Config.Load();
        var publicKey = Convert.FromBase64String(config.PolicySigningPublicKey!);

        var issued = await (await admin.PostAsync(new Uri(ApiRoutes.ComputerUninstallCode(agent.ComputerId), UriKind.Relative), null))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<UninstallCodeResponse>();
        Assert.StartsWith(UninstallAuthorization.Prefix, issued!.Code, StringComparison.Ordinal);
        Assert.Contains(issued.Code, issued.Command, StringComparison.Ordinal);
        var now = server.Clock.GetUtcNow();

        // Valid for this computer (checked with the key the agent pinned at enrollment) ...
        Assert.Null(UninstallAuthorization.Verify(issued.Code, agent.ComputerId, publicKey, now));
        // ... not for another one, not after 24 hours, and not when changed.
        Assert.NotNull(UninstallAuthorization.Verify(issued.Code, Guid.NewGuid(), publicKey, now));
        Assert.Contains("expired", UninstallAuthorization.Verify(issued.Code, agent.ComputerId, publicKey, now.AddHours(25)), StringComparison.Ordinal);
        var altered = issued.Code[..^2] + (issued.Code[^2] == 'A' ? "B" : "A") + issued.Code[^1];
        Assert.NotNull(UninstallAuthorization.Verify(altered, agent.ComputerId, publicKey, now));
        Assert.NotNull(UninstallAuthorization.Verify(null, agent.ComputerId, publicKey, now));
        Assert.NotNull(UninstallAuthorization.Verify("U1-short", agent.ComputerId, publicKey, now));

        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor8", AdminRoles.Auditor);
        using var auditor = server.Client(auditorToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsync(new Uri(ApiRoutes.ComputerUninstallCode(agent.ComputerId), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync(new Uri(ApiRoutes.ComputerUninstallCode(Guid.NewGuid()), UriKind.Relative), null)).StatusCode);

        var auditLog = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        var entry = Assert.Single(auditLog!.Items, e => e.Action == "computer.uninstall-code");
        Assert.DoesNotContain(issued.Code, entry.Details, StringComparison.Ordinal); // the code itself is not logged
    }

    [Fact]
    public async Task An_authorised_uninstall_raises_no_alert()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        await server.RunAlertEngineAsync();

        await agent.Runtime.NotifyStoppingAsync(windowsShuttingDown: false, TimeSpan.FromSeconds(5), authorisedUninstall: true);
        server.Clock.Advance(TimeSpan.FromHours(2));
        await server.RunAlertEngineAsync();

        using var later = await server.FreshOwnerClientAsync();
        var alerts = (await later.GetFromJsonAsync<PagedResult<AlertResponse>>($"{ApiRoutes.Alerts}?status=All"))!.Items;
        Assert.DoesNotContain(alerts, a => a.RuleCode is "agent-stopped" or "computer-not-reporting");
        var events = (await later.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?type=AgentStoppedOrUnavailable"))!.Items;
        Assert.Contains(events, e => e.Details!.Contains("uninstall code", StringComparison.Ordinal));
    }
}
