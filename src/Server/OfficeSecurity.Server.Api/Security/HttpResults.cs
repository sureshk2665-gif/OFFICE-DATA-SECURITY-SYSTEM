using OfficeSecurity.Server.Application.Common;

namespace OfficeSecurity.Server.Api.Security;

internal static class HttpResults
{
    public static RequestContext ToRequestContext(this HttpContext context) =>
        new(context.Items[SessionAuthenticationHandler.PrincipalItemKey] as CurrentPrincipal, context.Connection.RemoteIpAddress?.ToString());

    public static CurrentPrincipal RequirePrincipal(this HttpContext context) =>
        context.Items[SessionAuthenticationHandler.PrincipalItemKey] as CurrentPrincipal
        ?? throw new InvalidOperationException("Endpoint requires an authenticated principal.");

    public static Guid RequireComputerId(this HttpContext context) =>
        context.Items[DeviceAuthenticationHandler.ComputerIdItemKey] as Guid?
        ?? throw new InvalidOperationException("Endpoint requires an authenticated computer.");

    public static IResult ToHttp<T>(this Result<T> result) =>
        result.IsSuccess ? TypedResults.Ok(result.Value) : Problem(result.Error!);

    public static IResult ToHttpNoContent<T>(this Result<T> result) =>
        result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error!);

    public static IResult Problem(ServiceError error) =>
        TypedResults.Problem(
            detail: error.Message,
            statusCode: error.Kind switch
            {
                ErrorKind.Validation => StatusCodes.Status400BadRequest,
                ErrorKind.NotFound => StatusCodes.Status404NotFound,
                ErrorKind.Conflict => StatusCodes.Status409Conflict,
                ErrorKind.Unauthorized => StatusCodes.Status401Unauthorized,
                ErrorKind.Forbidden => StatusCodes.Status403Forbidden,
                _ => StatusCodes.Status500InternalServerError,
            });
}
