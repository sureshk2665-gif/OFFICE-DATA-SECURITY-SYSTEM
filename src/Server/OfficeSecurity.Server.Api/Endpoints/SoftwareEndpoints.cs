using Microsoft.AspNetCore.Http.Features;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Api.Endpoints;

internal static class SoftwareEndpoints
{
    public static void MapSoftwareEndpoints(this IEndpointRouteBuilder app)
    {
        // ---- staff: request software and follow their requests
        var staff = app.MapGroup(string.Empty).RequireAuthorization(Policies.Staff).WithTags("Software");

        staff.MapPost(ApiRoutes.SoftwareRequests, async (CreateSoftwareRequest request, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.CreateRequestAsync(request, http.ToRequestContext(), ct)).ToHttp());

        staff.MapGet(ApiRoutes.MySoftwareRequests, async (SoftwareService software, HttpContext http, CancellationToken ct) =>
            TypedResults.Ok(await software.ListMyRequestsAsync(http.ToRequestContext(), ct)));

        // ---- administrators: read
        var read = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminRead).WithTags("Software");

        read.MapGet(ApiRoutes.SoftwareRequests, async (SoftwareService software, int? page, int? pageSize, string? status, CancellationToken ct) =>
            TypedResults.Ok(await software.ListRequestsAsync(page ?? 1, pageSize ?? 50, status, ct)));

        read.MapGet(ApiRoutes.ApprovedSoftware, async (SoftwareService software, CancellationToken ct) =>
            TypedResults.Ok(await software.ListApprovedAsync(ct)));

        read.MapGet(ApiRoutes.SoftwareDeployments, async (SoftwareService software, int? page, int? pageSize, Guid? computerId, string? status, CancellationToken ct) =>
            TypedResults.Ok(await software.ListDeploymentsAsync(page ?? 1, pageSize ?? 50, computerId, status, null, ct)));

        read.MapGet(ApiRoutes.SoftwareInventory, async (SoftwareService software, string? search, bool? unapprovedOnly, CancellationToken ct) =>
            TypedResults.Ok(await software.ListTitlesAsync(search, unapprovedOnly ?? false, ct)));

        read.MapGet(ApiRoutes.SoftwareInventoryComputers, async (SoftwareService software, Guid? computerId, string? name, CancellationToken ct) =>
            TypedResults.Ok(await software.ListInstallationsAsync(computerId, name, ct)));

        // ---- administrators: change
        var write = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminWrite).WithTags("Software");

        write.MapPost(ApiRoutes.SoftwareRequests + "/{id:guid}/approve", async (Guid id, ApproveSoftwareRequest request, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.ApproveRequestAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.SoftwareRequests + "/{id:guid}/reject", async (Guid id, RejectSoftwareRequest request, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.RejectRequestAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.ApprovedSoftware, async (SaveApprovedSoftwareRequest request, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.CreateApprovedAsync(request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPut(ApiRoutes.ApprovedSoftware + "/{id:guid}", async (Guid id, SaveApprovedSoftwareRequest request, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.UpdateApprovedAsync(id, request, http.ToRequestContext(), ct)).ToHttp());

        write.MapDelete(ApiRoutes.ApprovedSoftware + "/{id:guid}", async (Guid id, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.DeleteApprovedAsync(id, http.ToRequestContext(), ct)).ToHttpNoContent());

        // The request body is the installer file itself (streamed to disk; up to 4 GB).
        write.MapPost(ApiRoutes.ApprovedSoftware + "/{id:guid}/packages", async (Guid id, string fileName, string installerType, string? silentArguments,
            string? signerSubject, bool? allowUnsigned, SoftwareService software, HttpContext http, CancellationToken ct) =>
        {
            if (http.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
            {
                limit.MaxRequestBodySize = SoftwareService.MaxPackageBytes;
            }

            var options = new UploadPackageOptions(fileName, installerType, silentArguments, signerSubject, allowUnsigned ?? false);
            return (await software.UploadPackageAsync(id, options, http.Request.Body, http.ToRequestContext(), ct)).ToHttp();
        });

        write.MapDelete(ApiRoutes.SoftwarePackages + "/{id:guid}", async (Guid id, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.DeletePackageAsync(id, http.ToRequestContext(), ct)).ToHttpNoContent());

        write.MapPost(ApiRoutes.SoftwareDeployments, async (CreateDeploymentRequest request, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.CreateDeploymentsAsync(request, http.ToRequestContext(), ct)).ToHttp());

        write.MapPost(ApiRoutes.SoftwareDeployments + "/{id:guid}/cancel", async (Guid id, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.CancelDeploymentAsync(id, http.ToRequestContext(), ct)).ToHttpNoContent());

        // ---- security agent (mutual TLS): only its own approved installation jobs
        var agent = app.MapGroup(string.Empty).RequireAuthorization(Policies.Computer).WithTags("Agent");

        agent.MapGet(ApiRoutes.AgentJobs, async (SoftwareService software, HttpContext http, CancellationToken ct) =>
            TypedResults.Ok(await software.GetAgentJobsAsync(http.RequireComputerId(), ct)));

        agent.MapPost(ApiRoutes.AgentJobs + "/{id:guid}/start", async (Guid id, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.StartJobAsync(http.RequireComputerId(), id, ct)).ToHttpNoContent());

        agent.MapGet(ApiRoutes.AgentJobs + "/{id:guid}/package", async (Guid id, SoftwareService software, HttpContext http, CancellationToken ct) =>
            await software.OpenJobPackageAsync(http.RequireComputerId(), id, ct) is { } package
                ? Results.Stream(package.Content, "application/octet-stream", package.FileName)
                : Results.NotFound());

        agent.MapPost(ApiRoutes.AgentJobs + "/{id:guid}/result", async (Guid id, AgentJobResult result, SoftwareService software, HttpContext http, CancellationToken ct) =>
            (await software.CompleteJobAsync(http.RequireComputerId(), id, result, ct)).ToHttpNoContent());
    }
}
