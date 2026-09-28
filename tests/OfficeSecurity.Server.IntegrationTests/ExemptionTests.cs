using System.Net;
using System.Net.Http.Json;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class ExemptionTests
{
    [Fact]
    public async Task Temporary_exception_is_signed_into_the_computers_policy_and_can_be_ended_early()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        await agent.StepAsync();
        var before = agent.Runtime.CurrentPolicy.Version;

        var created = await (await admin.PostAsJsonAsync(ApiRoutes.ComputerExemptions(agent.ComputerId),
                new CreateExemptionRequest(nameof(SecurityControl.RemovableStorage), "Copy the scanner's files", 120)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<ExemptionResponse>();
        Assert.True(created!.IsActive);
        Assert.Equal(server.Clock.GetUtcNow().AddMinutes(120), created.ExpiresAtUtc);

        // The agent receives a new, signed policy version that contains the exception.
        await agent.RunUntilAsync(() => agent.Runtime.CurrentPolicy.Version > before);
        var exception = Assert.Single(agent.Runtime.CurrentPolicy.Exceptions);
        Assert.Equal(SecurityControl.RemovableStorage, exception.Control);
        Assert.Equal("Copy the scanner's files", exception.Reason);

        var list = await admin.GetFromJsonAsync<List<ExemptionResponse>>(ApiRoutes.ComputerExemptions(agent.ComputerId));
        Assert.Equal(created.Id, Assert.Single(list!).Id);

        // Ended early: the next policy no longer contains it.
        var withException = agent.Runtime.CurrentPolicy.Version;
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync(new Uri(ApiRoutes.ComputerExemptionById(agent.ComputerId, created.Id), UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync(new Uri(ApiRoutes.ComputerExemptionById(agent.ComputerId, created.Id), UriKind.Relative))).StatusCode);
        await agent.RunUntilAsync(() => agent.Runtime.CurrentPolicy.Version > withException);
        Assert.Empty(agent.Runtime.CurrentPolicy.Exceptions);
        Assert.False(Assert.Single((await admin.GetFromJsonAsync<List<ExemptionResponse>>(ApiRoutes.ComputerExemptions(agent.ComputerId)))!).IsActive);

        var audit = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        Assert.Contains(audit!.Items, a => a.Action == "computer.exemption.create" && a.Details!.Contains("Copy the scanner's files", StringComparison.Ordinal));
        Assert.Contains(audit.Items, a => a.Action == "computer.exemption.revoke");
    }

    [Fact]
    public async Task Expired_exceptions_are_not_sent_to_the_computer()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        (await admin.PostAsJsonAsync(ApiRoutes.ComputerExemptions(agent.ComputerId),
            new CreateExemptionRequest(nameof(SecurityControl.BrowserRestrictions), "Supplier portal", 5))).EnsureSuccessStatusCode();

        server.Clock.Advance(TimeSpan.FromMinutes(6));
        // Any later policy change sends a new version; the expired exception is left out.
        var policies = await admin.GetFromJsonAsync<List<PolicySummary>>(ApiRoutes.Policies);
        var defaultPolicy = Assert.Single(policies!, p => p.IsDefault);
        var detail = await admin.GetFromJsonAsync<PolicyDetail>(ApiRoutes.PolicyById(defaultPolicy.Id));
        (await admin.PutAsJsonAsync(ApiRoutes.PolicyById(defaultPolicy.Id), new SavePolicyRequest(detail!.Name, "changed", detail.Settings))).EnsureSuccessStatusCode();
        var version = agent.Runtime.CurrentPolicy.Version;
        await agent.RunUntilAsync(() => agent.Runtime.CurrentPolicy.Version > version);

        Assert.Empty(agent.Runtime.CurrentPolicy.Exceptions);
    }

    [Theory]
    [InlineData("RemovableStorage", "ok reason", 4)]
    [InlineData("RemovableStorage", "ok reason", 43201)]
    [InlineData("RemovableStorage", "", 60)]
    [InlineData("AgentTamperProtection", "ok reason", 60)]
    [InlineData("NoSuchControl", "ok reason", 60)]
    public async Task Invalid_exceptions_are_refused(string control, string reason, int minutes)
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);

        var response = await admin.PostAsJsonAsync(ApiRoutes.ComputerExemptions(agent.ComputerId), new CreateExemptionRequest(control, reason, minutes));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Exceptions_need_an_approved_computer_and_an_administrator()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var waiting = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner));
        await waiting.StepAsync();
        var request = new CreateExemptionRequest(nameof(SecurityControl.RemovableStorage), "reason here", 60);

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(ApiRoutes.ComputerExemptions(waiting.ComputerId), request)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsJsonAsync(ApiRoutes.ComputerExemptions(Guid.NewGuid()), request)).StatusCode);

        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor3", AdminRoles.Auditor);
        var (_, staffToken) = await server.CreateActiveStaffAsync(owner, "EMP900", "Staff member pass 2026");
        using var auditor = server.Client(auditorToken);
        using var staff = server.Client(staffToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsJsonAsync(ApiRoutes.ComputerExemptions(waiting.ComputerId), request)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.PostAsJsonAsync(ApiRoutes.ComputerExemptions(waiting.ComputerId), request)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(new Uri(ApiRoutes.ComputerExemptions(waiting.ComputerId), UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri(ApiRoutes.ComputerExemptions(waiting.ComputerId), UriKind.Relative))).StatusCode);
    }
}
