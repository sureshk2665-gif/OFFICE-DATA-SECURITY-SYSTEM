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

public sealed record DeviceSummary(string InstanceId, string Name, string DeviceClass, string? Manufacturer, bool IsConnected, DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc);

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
