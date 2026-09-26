using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OfficeSecurity.Server.Application.Services;
using OfficeSecurity.Server.Infrastructure.Certificates;

namespace OfficeSecurity.Server.Api.Security;

/// <summary>
/// Authenticates security agents by their TLS client certificate (mutual TLS). The certificate must be
/// issued by this server's CA and belong to a computer that is currently approved.
/// </summary>
public sealed class DeviceAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    DeviceCertificateAuthority certificateAuthority,
    AgentService agents)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Device";
    public const string ComputerRole = "Computer";
    public const string ComputerIdItemKey = "OfficeSecurity.ComputerId";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var certificate = await Context.Connection.GetClientCertificateAsync(Context.RequestAborted);
        if (certificate is null)
        {
            return AuthenticateResult.NoResult();
        }

        if (!certificateAuthority.IsIssuedByThisCa(certificate))
        {
            return AuthenticateResult.Fail("Client certificate was not issued by this server.");
        }

        var computer = await agents.FindTrustedComputerAsync(DeviceCertificateAuthority.Thumbprint(certificate), Context.RequestAborted);
        if (computer is null)
        {
            return AuthenticateResult.Fail("Computer is not approved, or has been removed from management.");
        }

        Context.Items[ComputerIdItemKey] = computer.Value.Id;
        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, computer.Value.Id.ToString()),
            new Claim(ClaimTypes.Name, computer.Value.Hostname),
            new Claim(ClaimTypes.Role, ComputerRole),
        ], SchemeName);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
