using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Reports;

namespace OfficeSecurity.Server.Api.Endpoints;

internal static class ReportEndpoints
{
    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        // Administrators and auditors.
        var read = app.MapGroup(string.Empty).RequireAuthorization(Policies.AdminRead).WithTags("Reports");

        read.MapGet(ApiRoutes.Reports, () => TypedResults.Ok(ReportService.Types));

        read.MapGet(ApiRoutes.SavedReports, (ScheduledReports saved) => TypedResults.Ok(saved.List()));

        read.MapGet(ApiRoutes.SavedReports + "/{fileName}", (string fileName, ScheduledReports saved) =>
            saved.Read(fileName) is { } content
                ? Results.File(content, "application/pdf", fileName)
                : Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Report not found."));

        read.MapGet(ApiRoutes.Reports + "/{type}", async (string type, DateTimeOffset? from, DateTimeOffset? to, Guid? computerId, string? format,
            ReportService reports, HttpContext http, CancellationToken ct) =>
        {
            var result = await reports.CreateAsync(type, from, to, computerId, format, http.ToRequestContext(), ct);
            return result.Error is null
                ? Results.File(result.Value!.Content, result.Value.ContentType, result.Value.FileName)
                : result.ToHttp();
        });
    }
}
