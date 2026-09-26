using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OfficeSecurity.Server.Application.Services;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Api.Security;

/// <summary>
/// Authenticates "Authorization: Bearer &lt;token&gt;" against server-side sessions. Sessions are checked
/// on every request, so disabling an account or signing out takes effect immediately.
/// </summary>
public sealed class SessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AuthService auth)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Session";
    public const string PrincipalItemKey = "OfficeSecurity.CurrentPrincipal";
    public const string StaffRole = "Staff";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var principal = await auth.ValidateSessionAsync(header["Bearer ".Length..].Trim(), Context.RequestAborted);
        if (principal is null)
        {
            return AuthenticateResult.Fail("Session is not valid or has expired.");
        }

        Context.Items[PrincipalItemKey] = principal;

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, principal.Id.ToString()),
            new(ClaimTypes.Name, principal.LoginName),
            new("session_id", principal.SessionId.ToString()),
            new(ClaimTypes.Role, principal.Type == PrincipalType.Admin
                ? principal.Role!.Value.ToString()
                : StaffRole),
            new("principal_type", principal.Type.ToString()),
            new("display_name", principal.DisplayName),
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Bearer";
        return Task.CompletedTask;
    }
}
