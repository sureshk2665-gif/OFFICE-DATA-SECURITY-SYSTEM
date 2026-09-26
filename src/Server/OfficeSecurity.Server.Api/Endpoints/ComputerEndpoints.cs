using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Api.Endpoints;

internal static class ComputerEndpoints
{
    public const string EnrollmentRateLimit = "enrollment";

    public static void MapComputerEndpoints(this IEndpointRouteBuilder app)
    {
        // ---- agent, before approval (enrollment code / poll token)
        var enroll = app.MapGroup(string.Empty).AllowAnonymous().RequireRateLimiting(EnrollmentRateLimit).WithTags("Agent");

        enroll.MapPost(ApiRoutes.AgentEnroll, async (AgentEnrollRequest request, AgentService agents, HttpContext http, CancellationToken ct) =>
            (await agents.EnrollAsync(request, http.ToRequestContext(), ct)).ToHttp());

        enroll.MapPost(ApiRoutes.AgentEnrollStatus, async (AgentEnrollStatusRequest request, AgentService agents, CancellationToken ct) =>
            (await agents.GetEnrollmentStatusAsync(request, ct)).ToHttp());

        // ---- approved agent (mutual TLS)
        var agent = app.MapGroup(string.Empty).RequireAuthorization(Policies.Computer).WithTags("Agent");

        agent.MapPost(ApiRoutes.AgentHeartbeat, async (AgentHeartbeatRequest request, AgentService agents, HttpContext http, CancellationToken ct) =>
            TypedResults.Ok(await agents.HeartbeatAsync(http.RequireComputerId(), request, http.Connection.RemoteIpAddress?.ToString(), ct)));

        agent.MapGet(ApiRoutes.AgentPolicy, async (AgentService agents, HttpContext http, CancellationToken ct) =>
            TypedResults.Ok(await agents.GetPolicyAsync(http.RequireComputerId(), ct)));

        agent.MapPost(ApiRoutes.AgentInventory, async (AgentInventoryRequest request, AgentService agents, HttpContext http, CancellationToken ct) =>
            (await agents.ReportInventoryAsync(http.RequireComputerId(), request, ct)).ToHttpNoContent());

        agent.MapPost(ApiRoutes.AgentEvents, async (AgentEventsRequest request, AgentService agents, HttpContext http, CancellationToken ct) =>
            (await agents.ReportEventsAsync(http.RequireComputerId(), request, ct)).ToHttp());

        agent.MapPost(ApiRoutes.AgentLoginTicket, (AgentService agents, HttpContext http) =>
            TypedResults.Ok(agents.IssueLoginTicket(http.RequireComputerId())));

        // ---- administrators: read
        var read = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminRead).WithTags("Computers");

        read.MapGet(ApiRoutes.Computers, async (ComputerAdministration computers, int? page, int? pageSize, string? search, string? status, CancellationToken ct) =>
            TypedResults.Ok(await computers.ListAsync(page ?? 1, pageSize ?? 50, search, status, ct)));

        read.MapGet(ApiRoutes.Computers + "/{id:guid}", async (Guid id, ComputerAdministration computers, CancellationToken ct) =>
            (await computers.GetAsync(id, ct)).ToHttp());

        read.MapGet(ApiRoutes.Events, async (ComputerAdministration computers, int? page, int? pageSize, Guid? computerId, string? search, CancellationToken ct) =>
            TypedResults.Ok(await computers.ListEventsAsync(page ?? 1, pageSize ?? 50, computerId, search, ct)));

        read.MapGet(ApiRoutes.Policies, async (PolicyService policies, CancellationToken ct) =>
            TypedResults.Ok(await policies.ListAsync(ct)));

        read.MapGet(ApiRoutes.Policies + "/{id:guid}", async (Guid id, PolicyService policies, CancellationToken ct) =>
            (await policies.GetAsync(id, ct)).ToHttp());

        // ---- administrators: change
        var write = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminWrite).WithTags("Computers");

        write.MapPost(ApiRoutes.EnrollmentCodes, async (ComputerAdministration computers, HttpContext http, CancellationToken ct) =>
            TypedResults.Ok(await computers.CreateEnrollmentCodeAsync(http.ToRequestContext(), ct)));

        write.MapPost(ApiRoutes.Computers + "/{id:guid}/approve", async (Guid id, ComputerAdministration computers, HttpContext http, CancellationToken ct) =>
            (await computers.ApproveAsync(id, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Computers + "/{id:guid}/reject", async (Guid id, ComputerAdministration computers, HttpContext http, CancellationToken ct) =>
            (await computers.RejectAsync(id, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Computers + "/{id:guid}/retire", async (Guid id, ComputerAdministration computers, HttpContext http, CancellationToken ct) =>
            (await computers.RetireAsync(id, http.ToRequestContext(), ct)).ToHttp());

        write.MapPut(ApiRoutes.Computers + "/{id:guid}/policy", async (Guid id, AssignPolicyRequest request, ComputerAdministration computers, HttpContext http, CancellationToken ct) =>
            (await computers.AssignPolicyAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPut(ApiRoutes.Computers + "/{id:guid}/staff", async (Guid id, AssignStaffRequest request, ComputerAdministration computers, HttpContext http, CancellationToken ct) =>
            (await computers.AssignStaffAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Policies, async (SavePolicyRequest request, PolicyService policies, HttpContext http, CancellationToken ct) =>
            (await policies.CreateAsync(request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPut(ApiRoutes.Policies + "/{id:guid}", async (Guid id, SavePolicyRequest request, PolicyService policies, HttpContext http, CancellationToken ct) =>
            (await policies.UpdateAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapDelete(ApiRoutes.Policies + "/{id:guid}", async (Guid id, PolicyService policies, HttpContext http, CancellationToken ct) =>
            (await policies.DeleteAsync(id, http.ToRequestContext(), ct)).ToHttpNoContent());
    }
}
