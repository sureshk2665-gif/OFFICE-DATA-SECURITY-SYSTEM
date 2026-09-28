namespace OfficeSecurity.Contracts;

public static class ComputerStatuses
{
    public const string PendingApproval = "PendingApproval";
    public const string Trusted = "Trusted";
    public const string Rejected = "Rejected";
    public const string Retired = "Retired";
}

/// <summary>A new enrollment code, shown to the administrator once, with what is needed to install the agent.</summary>
public sealed record EnrollmentCodeResponse(string EnrollmentCode, DateTimeOffset ExpiresAtUtc, string PairingCode);

public sealed record ComputerSummary(
    Guid Id,
    string Hostname,
    string Status,
    bool IsOnline,
    DateTimeOffset? LastSeenAtUtc,
    string? OsName,
    string? OsEdition,
    string? AgentVersion,
    string? PolicyName,
    long AppliedPolicyVersion,
    long LatestPolicyVersion,
    int FailedControls,
    DateTimeOffset RegisteredAtUtc);

public sealed record DeviceSummary(string InstanceId, string Name, string DeviceClass, string? Manufacturer, bool IsConnected, DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc, string? ParentInstanceId = null);

public sealed record StaffReference(Guid Id, string EmployeeCode, string DisplayName);

public sealed record ComputerDetail(
    ComputerSummary Summary,
    HardwareInventory? Hardware,
    IReadOnlyList<ControlStatus> Controls,
    IReadOnlyList<DeviceSummary> Devices,
    IReadOnlyList<StaffReference> AssignedStaff,
    Guid? PolicyId,
    string? LastSeenIp,
    string? CertificateThumbprint,
    DateTimeOffset? CertificateExpiresAtUtc);

public sealed record AssignPolicyRequest(Guid? PolicyId);

public sealed record AssignStaffRequest(IReadOnlyList<Guid> StaffIds);

public sealed record SecurityEventResponse(
    long Id,
    Guid ComputerId,
    string ComputerName,
    string EventType,
    string Severity,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset ReceivedAtUtc,
    string? Details);

/// <summary>A temporary exception to one security control on one computer.</summary>
public sealed record ExemptionResponse(
    Guid Id,
    Guid ComputerId,
    string Control,
    string Reason,
    DateTimeOffset StartsAtUtc,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset CreatedAtUtc,
    string? CreatedBy,
    bool IsActive,
    DateTimeOffset? RevokedAtUtc);

/// <summary>Starts now and lasts <paramref name="DurationMinutes"/> (5 minutes to 30 days).</summary>
public sealed record CreateExemptionRequest(string Control, string Reason, int DurationMinutes);

public static class Exemptions
{
    public const int MinMinutes = 5;
    public const int MaxMinutes = 30 * 24 * 60;

    /// <summary>Controls that can be lifted temporarily for one computer.</summary>
    public static readonly IReadOnlyList<SecurityControl> AllowedControls =
    [
        SecurityControl.RemovableStorage,
        SecurityControl.MobileDeviceTransfer,
        SecurityControl.SoftwareInstallation,
        SecurityControl.NetworkRestrictions,
        SecurityControl.BrowserRestrictions,
    ];
}

/// <summary>A BitLocker recovery key on file (the key itself is only shown by <see cref="RecoveryKeyRevealResponse"/>).</summary>
public sealed record RecoveryKeyResponse(long Id, string Drive, string ProtectorId, DateTimeOffset FirstReportedUtc, DateTimeOffset LastReportedUtc);

public sealed record RecoveryKeyRevealResponse(long Id, string Drive, string RecoveryPassword);

/// <summary>Permission to remove the agent from one computer (valid 24 hours), and the command to use it.</summary>
public sealed record UninstallCodeResponse(string Code, DateTimeOffset ExpiresAtUtc, string Command);
