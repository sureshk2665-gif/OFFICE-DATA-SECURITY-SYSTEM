using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Api.Endpoints;

internal static class AlertEndpoints
{
    public static void MapAlertEndpoints(this IEndpointRouteBuilder app)
    {
        var read = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminRead).WithTags("Alerts");

        read.MapGet(ApiRoutes.Alerts, async (AlertService alerts, int? page, int? pageSize, string? status, string? severity, Guid? computerId, string? search, CancellationToken ct) =>
            TypedResults.Ok(await alerts.ListAsync(page ?? 1, pageSize ?? 50, status, severity, computerId, search, ct)));

        read.MapGet(ApiRoutes.AlertSummary, async (AlertService alerts, CancellationToken ct) =>
            TypedResults.Ok(await alerts.SummaryAsync(ct)));

        read.MapGet(ApiRoutes.AlertRules, async (AlertService alerts, CancellationToken ct) =>
            TypedResults.Ok(await alerts.ListRulesAsync(ct)));

        var write = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminWrite).WithTags("Alerts");

        write.MapPost(ApiRoutes.Alerts + "/{id:guid}/acknowledge", async (Guid id, AlertService alerts, HttpContext http, CancellationToken ct) =>
            (await alerts.AcknowledgeAsync(id, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Alerts + "/{id:guid}/resolve", async (Guid id, ResolveAlertRequest request, AlertService alerts, HttpContext http, CancellationToken ct) =>
            (await alerts.ResolveAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPut(ApiRoutes.AlertRules + "/{code}", async (string code, UpdateAlertRuleRequest request, AlertService alerts, HttpContext http, CancellationToken ct) =>
            (await alerts.UpdateRuleAsync(code, request, http.ToRequestContext(), ct)).ToHttp());
    }
}
