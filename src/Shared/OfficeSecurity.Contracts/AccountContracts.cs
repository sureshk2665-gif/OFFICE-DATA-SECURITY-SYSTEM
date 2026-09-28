namespace OfficeSecurity.Contracts;

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int TotalCount);

public sealed record StaffSummary(
    Guid Id,
    string EmployeeCode,
    string DisplayName,
    string? Department,
    string Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? LastLoginAtUtc,
    bool IsLocked);

public sealed record CreateStaffRequest(string EmployeeCode, string DisplayName, string? Department);

public sealed record UpdateStaffRequest(string DisplayName, string? Department);

/// <summary>A one-time setup code, shown to the administrator exactly once.</summary>
public sealed record SetupCodeResponse(Guid AccountId, string LoginName, string SetupCode, DateTimeOffset ExpiresAtUtc);

public sealed record AdminSummary(
    Guid Id,
    string Username,
    string DisplayName,
    string Role,
    string Status,
    bool MfaEnabled,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? LastLoginAtUtc);

public sealed record CreateAdminRequest(string Username, string DisplayName, string Role);

public static class AccountStatuses
{
    public const string PendingActivation = "PendingActivation";
    public const string Active = "Active";
    public const string Disabled = "Disabled";
}

public sealed record AuditEntryResponse(
    long Id,
    DateTimeOffset OccurredAtUtc,
    string ActorType,
    string? ActorName,
    string Action,
    string Outcome,
    string? TargetType,
    string? TargetId,
    string? SourceIp,
    string? Details);

public sealed record AuditVerificationResponse(bool IsIntact, long EntriesChecked, long? FirstBrokenEntryId, string Message);

public sealed record DashboardOverviewResponse(
    int StaffTotal,
    int StaffActive,
    int StaffPendingActivation,
    int StaffDisabled,
    int AdministratorsActive,
    int FailedLoginsLast24Hours,
    int ComputersTrusted,
    int ComputersOnline,
    int ComputersOffline,
    int ComputersPendingApproval,
    int ComputersWithFailedControls,
    int PendingSoftwareRequests,
    int ComputersWithUnapprovedSoftware,
    int OpenAlerts = 0,
    int OpenCriticalAlerts = 0);
