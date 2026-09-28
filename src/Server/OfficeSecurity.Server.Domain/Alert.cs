namespace OfficeSecurity.Server.Domain;

public enum AlertStatus
{
    Open,
    Acknowledged,
    Resolved,
}

/// <summary>
/// Something an administrator should look at. Repeats of the same problem (same rule, computer and subject) are
/// added to the open alert instead of creating new ones.
/// </summary>
public sealed class Alert
{
    public Guid Id { get; set; }

    public required string RuleCode { get; set; }

    public required string Severity { get; set; }

    public Guid? ComputerId { get; set; }

    /// <summary>What the alert is about within the computer (e.g. an account name); empty when the computer is enough.</summary>
    public string Subject { get; set; } = string.Empty;

    public required string Title { get; set; }

    public string? Details { get; set; }

    public long? FirstEventId { get; set; }

    public long? LastEventId { get; set; }

    public int EventCount { get; set; }

    public DateTimeOffset FirstSeenUtc { get; set; }

    public DateTimeOffset LastSeenUtc { get; set; }

    public AlertStatus Status { get; set; }

    public string? AcknowledgedBy { get; set; }

    public DateTimeOffset? AcknowledgedAtUtc { get; set; }

    public string? ResolvedBy { get; set; }

    public DateTimeOffset? ResolvedAtUtc { get; set; }

    public string? ResolutionNote { get; set; }
}

/// <summary>An administrator's settings for one alert rule (defaults are in code until first changed).</summary>
public sealed class AlertRuleSetting
{
    public required string Code { get; set; }

    public bool Enabled { get; set; }

    public required string Severity { get; set; }

    public int Threshold { get; set; }

    public int WindowMinutes { get; set; }

    public string? UpdatedBy { get; set; }

    public DateTimeOffset? UpdatedAtUtc { get; set; }
}

/// <summary>Small server state values (e.g. how far the alert engine has read the events).</summary>
public sealed class SystemSetting
{
    public required string Key { get; set; }

    public required string Value { get; set; }
}
