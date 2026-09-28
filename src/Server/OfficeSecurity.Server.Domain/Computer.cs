namespace OfficeSecurity.Server.Domain;

/// <summary>An office computer running the security agent.</summary>
public sealed class Computer
{
    public Guid Id { get; set; }

    public required string Hostname { get; set; }

    public ComputerStatus Status { get; set; }

    public Guid EnrollmentCodeId { get; set; }

    /// <summary>Certificate request submitted at enrollment (public key only).</summary>
    public string? CertificateRequestPem { get; set; }

    /// <summary>SHA-256 of the poll token used until approval.</summary>
    public string? PollTokenHash { get; set; }

    public string? CertificatePem { get; set; }

    /// <summary>SHA-256 thumbprint (hex) of the issued client certificate; the computer's identity for mutual TLS.</summary>
    public string? CertificateThumbprint { get; set; }

    public DateTimeOffset? CertificateExpiresAtUtc { get; set; }

    public DateTimeOffset RegisteredAtUtc { get; set; }

    public DateTimeOffset? DecidedAtUtc { get; set; }

    public Guid? DecidedByAdminId { get; set; }

    public DateTimeOffset? LastSeenAtUtc { get; set; }

    public string? LastSeenIp { get; set; }

    public string? AgentVersion { get; set; }

    /// <summary>Latest hardware/OS report (JSON of HardwareInventory).</summary>
    public string? HardwareJson { get; set; }

    public string? OsName { get; set; }

    public string? OsEdition { get; set; }

    /// <summary>Latest per-control status report (JSON array of ControlStatus).</summary>
    public string? ControlStatusJson { get; set; }

    public int FailedControls { get; set; }

    public int HeartbeatIntervalSeconds { get; set; } = 60;

    /// <summary>Assigned policy; <c>null</c> means the default policy.</summary>
    public Guid? PolicyId { get; set; }

    /// <summary>
    /// Version of this computer's effective policy. Incremented whenever the assigned policy or its content
    /// changes, so agents always see a strictly increasing version.
    /// </summary>
    public long PolicyVersion { get; set; } = 1;

    public long AppliedPolicyVersion { get; set; }
}

public sealed class EnrollmentCode
{
    public Guid Id { get; set; }

    public required string CodeHash { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset ExpiresAtUtc { get; set; }

    public DateTimeOffset? UsedAtUtc { get; set; }

    public Guid CreatedByAdminId { get; set; }
}

/// <summary>A removable or wireless device seen on a computer (USB storage, phone, Bluetooth...).</summary>
public sealed class DeviceInventoryItem
{
    public long Id { get; set; }

    public Guid ComputerId { get; set; }

    public required string InstanceId { get; set; }

    public required string Name { get; set; }

    public required string DeviceClass { get; set; }

    public string? Manufacturer { get; set; }

    public bool IsConnected { get; set; }

    public DateTimeOffset FirstSeenUtc { get; set; }

    public DateTimeOffset LastSeenUtc { get; set; }
}

/// <summary>A security event reported by an agent.</summary>
public sealed class SecurityEvent
{
    public long Id { get; set; }

    public Guid ComputerId { get; set; }

    /// <summary>Agent-generated id; unique per computer so retried uploads are not stored twice.</summary>
    public Guid EventId { get; set; }

    public required string EventType { get; set; }

    public required string Severity { get; set; }

    public DateTimeOffset OccurredAtUtc { get; set; }

    public DateTimeOffset ReceivedAtUtc { get; set; }

    public string? Details { get; set; }
}

public sealed class PolicyDefinition
{
    public Guid Id { get; set; }

    public required string Name { get; set; }

    public string? Description { get; set; }

    /// <summary>Exactly one policy is the default for computers without an explicit assignment.</summary>
    public bool IsDefault { get; set; }

    /// <summary>JSON of PolicySettings.</summary>
    public required string SettingsJson { get; set; }

    public int Revision { get; set; } = 1;

    public DateTimeOffset UpdatedAtUtc { get; set; }

    public Guid? UpdatedByAdminId { get; set; }
}

/// <summary>A staff member allowed to sign in on a computer.</summary>
public sealed class StaffComputerAssignment
{
    public Guid StaffId { get; set; }

    public Guid ComputerId { get; set; }

    public DateTimeOffset AssignedAtUtc { get; set; }

    public Guid AssignedByAdminId { get; set; }
}

/// <summary>
/// A time-limited exception for one security control on one computer (e.g. "allow USB drives on PC-07 for
/// two hours"). Included in the computer's signed policy; the agent lifts the control only while it is active.
/// </summary>
public sealed class ControlExemption
{
    public Guid Id { get; set; }

    public Guid ComputerId { get; set; }

    public required string Control { get; set; }

    public required string Reason { get; set; }

    public DateTimeOffset StartsAtUtc { get; set; }

    public DateTimeOffset ExpiresAtUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public Guid CreatedByAdminId { get; set; }

    public DateTimeOffset? RevokedAtUtc { get; set; }

    public Guid? RevokedByAdminId { get; set; }
}
