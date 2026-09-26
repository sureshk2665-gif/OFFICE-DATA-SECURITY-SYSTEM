using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Common;

/// <summary>The signed-in principal making a request.</summary>
public sealed record CurrentPrincipal(PrincipalType Type, Guid Id, string LoginName, string DisplayName, AdminRole? Role, Guid SessionId);

/// <summary>Who is acting and from where; used for authorization decisions and audit records.</summary>
public sealed record RequestContext(CurrentPrincipal? Principal, string? SourceIp)
{
    public static RequestContext Anonymous(string? sourceIp) => new(null, sourceIp);

    public static readonly RequestContext System = new(null, null);
}
