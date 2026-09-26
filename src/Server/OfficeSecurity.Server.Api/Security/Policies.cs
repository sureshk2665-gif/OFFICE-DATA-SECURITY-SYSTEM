using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Api.Security;

/// <summary>Authorization policies. Every endpoint requires a signed-in user unless explicitly anonymous.</summary>
public static class Policies
{
    /// <summary>Any administrator, including read-only auditors.</summary>
    public const string AdminRead = nameof(AdminRead);

    /// <summary>Administrators who may change data.</summary>
    public const string AdminWrite = nameof(AdminWrite);

    /// <summary>Manages administrator accounts.</summary>
    public const string SuperAdmin = nameof(SuperAdmin);

    public const string Staff = nameof(Staff);

    /// <summary>An approved computer's security agent (mutual TLS).</summary>
    public const string Computer = nameof(Computer);

    public static void Configure(Microsoft.AspNetCore.Authorization.AuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder(SessionAuthenticationHandler.SchemeName)
            .RequireAuthenticatedUser()
            .Build();

        options.AddPolicy(AdminRead, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName)
            .RequireRole(nameof(AdminRole.SuperAdmin), nameof(AdminRole.Admin), nameof(AdminRole.Auditor)));
        options.AddPolicy(AdminWrite, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName)
            .RequireRole(nameof(AdminRole.SuperAdmin), nameof(AdminRole.Admin)));
        options.AddPolicy(SuperAdmin, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName)
            .RequireRole(nameof(AdminRole.SuperAdmin)));
        options.AddPolicy(Staff, p => p.AddAuthenticationSchemes(SessionAuthenticationHandler.SchemeName)
            .RequireRole(SessionAuthenticationHandler.StaffRole));
        options.AddPolicy(Computer, p => p.AddAuthenticationSchemes(DeviceAuthenticationHandler.SchemeName)
            .RequireRole(DeviceAuthenticationHandler.ComputerRole));
    }
}
