namespace OfficeSecurity.Contracts;

public static class AlertStatuses
{
    public const string Open = "Open";
    public const string Acknowledged = "Acknowledged";
    public const string Resolved = "Resolved";

    /// <summary>List filter: open and acknowledged (everything not resolved).</summary>
    public const string Active = "Active";
}

public sealed record AlertResponse(
    Guid Id,
    string RuleCode,
    string RuleName,
    string Severity,
    Guid? ComputerId,
    string? ComputerName,
    string Title,
    string? Details,
    int EventCount,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    string Status,
    string? AcknowledgedBy,
    DateTimeOffset? AcknowledgedAtUtc,
    string? ResolvedBy,
    DateTimeOffset? ResolvedAtUtc,
    string? ResolutionNote);

/// <summary>Counts for the dashboard badge and overview.</summary>
public sealed record AlertSummaryResponse(int Open, int OpenCritical, int Acknowledged, DateTimeOffset? LatestAtUtc);

public sealed record ResolveAlertRequest(string? Note);

public sealed record AlertRuleResponse(
    string Code,
    string Name,
    string Description,
    bool Enabled,
    string Severity,
    int Threshold,
    int WindowMinutes,
    string? ThresholdMeaning,
    bool UsesWindow,
    string? UpdatedBy,
    DateTimeOffset? UpdatedAtUtc);

public sealed record UpdateAlertRuleRequest(bool Enabled, string Severity, int Threshold, int WindowMinutes);

/// <summary>A report the server can create.</summary>
public sealed record ReportTypeInfo(string Code, string Name, string Description, bool UsesPeriod, bool UsesComputer);

public static class ReportFormats
{
    public const string Csv = "csv";
    public const string Pdf = "pdf";
}

/// <summary>A report saved automatically on the server (weekly and monthly summaries).</summary>
public sealed record SavedReportInfo(string FileName, string Title, DateTimeOffset CreatedUtc, long SizeBytes);
