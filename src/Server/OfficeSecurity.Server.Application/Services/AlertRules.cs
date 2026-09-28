using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>How a rule finds problems.</summary>
public enum AlertRuleKind
{
    /// <summary>Raised by events from computers: at least <c>Threshold</c> matching events on one computer within <c>WindowMinutes</c>.</summary>
    Event,

    /// <summary>Checked every run against the current state (computers, audit log); resolved automatically when the problem is gone.</summary>
    State,
}

public sealed record AlertRuleDefinition(
    string Code,
    string Name,
    string Description,
    AlertRuleKind Kind,
    string DefaultSeverity,
    bool EnabledByDefault = true,
    int DefaultThreshold = 1,
    int DefaultWindowMinutes = 60,
    string? ThresholdMeaning = null,
    bool UsesWindow = false,
    SecurityEventType[]? EventTypes = null,
    Func<SecurityEvent, bool>? Matches = null,
    Func<string, string>? Title = null);

/// <summary>The alert rules. Administrators can switch each one off and change its severity and numbers.</summary>
public static class AlertRules
{
    public const string Tamper = "tamper";
    public const string UsbBlocked = "usb-blocked";
    public const string ProgramBlocked = "program-blocked";
    public const string Ransomware = "ransomware";
    public const string UnapprovedSoftware = "unapproved-software";
    public const string AgentStopped = "agent-stopped";
    public const string WindowsFailedSignIns = "windows-failed-sign-ins";
    public const string SystemFailedSignIns = "system-failed-sign-ins";
    public const string ComputerNotReporting = "computer-not-reporting";
    public const string ProtectionFailed = "protection-failed";
    public const string ComputerWaiting = "computer-waiting";
    public const string AuditIntegrity = "audit-integrity";

    public static IReadOnlyList<AlertRuleDefinition> All { get; } =
    [
        new(Tamper, "Protection tampered with",
            "Someone changed or removed a protection on a computer (the agent has put it back).",
            AlertRuleKind.Event, EventSeverities.Critical,
            EventTypes: [SecurityEventType.PolicyTamperAttempt],
            Title: pc => $"Protection tampered with on {pc}"),
        new(UsbBlocked, "Blocked USB drive or phone",
            "A USB drive, memory card or phone was connected and blocked.",
            AlertRuleKind.Event, EventSeverities.Warning,
            EventTypes: [SecurityEventType.RemovableStorageBlocked, SecurityEventType.UnauthorizedUsbConnection, SecurityEventType.FileTransferBlocked],
            Title: pc => $"Blocked USB drive or phone on {pc}"),
        new(ProgramBlocked, "Blocked program",
            "Application Control stopped a program that is not allowed (Enforce mode only; Audit-mode reports do not raise alerts).",
            AlertRuleKind.Event, EventSeverities.Warning,
            EventTypes: [SecurityEventType.UnauthorizedApplicationBlocked],
            Matches: e => e.Severity != EventSeverities.Information,
            Title: pc => $"Program blocked on {pc}"),
        new(Ransomware, "Ransomware protection blocked a program",
            "A program tried to change files in a protected company folder and Windows stopped it.",
            AlertRuleKind.Event, EventSeverities.Critical,
            EventTypes: [SecurityEventType.PolicyViolation],
            Matches: e => e.Details?.StartsWith("Ransomware protection blocked", StringComparison.Ordinal) == true,
            Title: pc => $"Ransomware protection blocked a program on {pc}"),
        new(UnapprovedSoftware, "Program installed that is not approved",
            "A program appeared on a computer that is not on the approved software list.",
            AlertRuleKind.Event, EventSeverities.Warning,
            EventTypes: [SecurityEventType.SoftwareInstalled],
            Matches: e => e.Severity != EventSeverities.Information,
            Title: pc => $"Unapproved program installed on {pc}"),
        new(AgentStopped, "Agent stopped",
            "The security agent was stopped while Windows kept running. Only an administrator of that computer can do this.",
            AlertRuleKind.Event, EventSeverities.Critical,
            EventTypes: [SecurityEventType.AgentStoppedOrUnavailable],
            Matches: e => e.Severity != EventSeverities.Information,
            Title: pc => $"Security agent stopped on {pc}"),
        new(WindowsFailedSignIns, "Repeated failed Windows sign-ins",
            "Many wrong passwords at the Windows sign-in of one computer in a short time (needs 'Record Windows sign-ins' in the policy).",
            AlertRuleKind.Event, EventSeverities.Warning, DefaultThreshold: 5, DefaultWindowMinutes: 15,
            ThresholdMeaning: "failed sign-ins", UsesWindow: true,
            EventTypes: [SecurityEventType.FailedLogin],
            Title: pc => $"Repeated failed Windows sign-ins on {pc}"),
        new(SystemFailedSignIns, "Repeated failed sign-ins to this system",
            "Many failed sign-ins to the dashboard or staff app for one account name in a short time.",
            AlertRuleKind.State, EventSeverities.Warning, DefaultThreshold: 5, DefaultWindowMinutes: 15,
            ThresholdMeaning: "failed sign-ins", UsesWindow: true),
        new(ComputerNotReporting, "Computer not reporting",
            "An approved computer has not contacted the server for a while, and it was not shut down normally (a computer switched off at night does not raise this alert).",
            AlertRuleKind.State, EventSeverities.Warning, DefaultThreshold: 60,
            ThresholdMeaning: "minutes without contact"),
        new(ProtectionFailed, "Protection not working",
            "A computer reports that a protection its policy requires could not be applied or verified.",
            AlertRuleKind.State, EventSeverities.Warning),
        new(ComputerWaiting, "Computer waiting for approval",
            "A computer has registered and is waiting to be approved or rejected.",
            AlertRuleKind.State, EventSeverities.Information),
        new(AuditIntegrity, "Audit log integrity problem",
            "The automatic check (every 6 hours) found that the audit log was altered.",
            AlertRuleKind.State, EventSeverities.Critical),
    ];

    public static AlertRuleDefinition? Find(string code) => All.FirstOrDefault(r => r.Code == code);

    /// <summary>A rule's settings: the administrator's saved values, or the defaults.</summary>
    public static AlertRuleSetting Effective(AlertRuleDefinition rule, AlertRuleSetting? saved) => saved ?? new AlertRuleSetting
    {
        Code = rule.Code,
        Enabled = rule.EnabledByDefault,
        Severity = rule.DefaultSeverity,
        Threshold = rule.DefaultThreshold,
        WindowMinutes = rule.DefaultWindowMinutes,
    };
}
