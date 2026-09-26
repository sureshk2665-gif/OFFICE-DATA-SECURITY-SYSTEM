using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Api.Endpoints;

internal static class AdministrationEndpoints
{
    public static void MapAdministrationEndpoints(this IEndpointRouteBuilder app)
    {
        // ---- read-only (all administrator roles, including auditors)
        var read = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminRead).WithTags("Administration");

        read.MapGet(ApiRoutes.DashboardOverview, async (AccountAdministration accounts, CancellationToken ct) =>
            TypedResults.Ok(await accounts.GetOverviewAsync(ct)));

        read.MapGet(ApiRoutes.Staff, async (AccountAdministration accounts, int? page, int? pageSize, string? search, string? status, CancellationToken ct) =>
            TypedResults.Ok(await accounts.ListStaffAsync(page ?? 1, pageSize ?? 50, search, status, ct)));

        read.MapGet(ApiRoutes.Staff + "/{id:guid}", async (Guid id, AccountAdministration accounts, CancellationToken ct) =>
            (await accounts.GetStaffAsync(id, ct)).ToHttp());

        read.MapGet(ApiRoutes.Admins, async (AccountAdministration accounts, CancellationToken ct) =>
            TypedResults.Ok(await accounts.ListAdminsAsync(ct)));

        read.MapGet(ApiRoutes.Audit, async (AuditLog audit, int? page, int? pageSize, string? search, DateTimeOffset? from, DateTimeOffset? to, CancellationToken ct) =>
            TypedResults.Ok(await audit.ListAsync(page ?? 1, pageSize ?? 50, search, from, to, ct)));

        read.MapGet(ApiRoutes.AuditVerify, async (AuditLog audit, CancellationToken ct) =>
            TypedResults.Ok(await audit.VerifyAsync(ct)));

        // ---- staff management (administrators who may change data)
        var write = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminWrite).WithTags("Administration");

        write.MapPost(ApiRoutes.Staff, async (CreateStaffRequest request, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.CreateStaffAsync(request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPut(ApiRoutes.Staff + "/{id:guid}", async (Guid id, UpdateStaffRequest request, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.UpdateStaffAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Staff + "/{id:guid}/disable", async (Guid id, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.DisableStaffAsync(id, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Staff + "/{id:guid}/enable", async (Guid id, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.EnableStaffAsync(id, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.Staff + "/{id:guid}/reset", async (Guid id, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.ResetStaffAsync(id, http.ToRequestContext(), ct)).ToHttp());

        // ---- administrator management (super administrators only)
        var super = app.MapGroup(string.Empty).RequireAuthorization(Policies.SuperAdmin).WithTags("Administration");

        super.MapPost(ApiRoutes.Admins, async (CreateAdminRequest request, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.CreateAdminAsync(request, http.ToRequestContext(), ct)).ToHttp());

        super.MapPost(ApiRoutes.Admins + "/{id:guid}/disable", async (Guid id, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.DisableAdminAsync(id, http.ToRequestContext(), ct)).ToHttp());

        super.MapPost(ApiRoutes.Admins + "/{id:guid}/enable", async (Guid id, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.EnableAdminAsync(id, http.ToRequestContext(), ct)).ToHttp());

        super.MapPost(ApiRoutes.Admins + "/{id:guid}/reset", async (Guid id, AccountAdministration accounts, HttpContext http, CancellationToken ct) =>
            (await accounts.ResetAdminAsync(id, http.ToRequestContext(), ct)).ToHttp());
    }
}
