namespace OfficeSecurity.Contracts;

public sealed record SetupStatusResponse(bool FirstAdminSetupRequired);

public sealed record FirstAdminSetupRequest(string SetupCode, string Username, string DisplayName, string Password);

public sealed record AdminActivateRequest(string Username, string SetupCode, string NewPassword);

/// <summary>
/// Returned once when an administrator sets up two-step verification. The secret must be added to an
/// authenticator app (Microsoft Authenticator, Google Authenticator...) and confirmed with a code.
/// </summary>
public sealed record MfaEnrollmentResponse(string EnrollmentTicket, string SecretBase32, string OtpAuthUri);

public sealed record ConfirmMfaRequest(string EnrollmentTicket, string Code);

public sealed record AdminLoginRequest(string Username, string Password);

public sealed record AdminLoginResponse(string MfaTicket);

public sealed record AdminMfaRequest(string MfaTicket, string Code);

/// <param name="ComputerTicket">From the agent on this computer; required when the staff member is restricted to assigned computers.</param>
public sealed record StaffLoginRequest(string EmployeeCode, string Password, string? ComputerTicket = null);

public sealed record StaffActivateRequest(string EmployeeCode, string SetupCode, string NewPassword, string? ComputerTicket = null);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record SessionResponse(string Token, DateTimeOffset ExpiresAtUtc, CurrentUserResponse User);

public sealed record CurrentUserResponse(Guid Id, string AccountType, string LoginName, string DisplayName, string? Role);

public static class AccountTypes
{
    public const string Admin = "Admin";
    public const string Staff = "Staff";
}

public static class AdminRoles
{
    public const string SuperAdmin = "SuperAdmin";
    public const string Admin = "Admin";
    public const string Auditor = "Auditor";

    public static readonly IReadOnlyList<string> All = [SuperAdmin, Admin, Auditor];
}
