namespace OfficeSecurity.Contracts;

/// <summary>
/// Verified state of a security control on a computer. A control is only reported as
/// <see cref="Enforced"/> after the agent has read back the effective operating-system setting.
/// </summary>
public enum ControlState
{
    /// <summary>The agent has not checked this control yet.</summary>
    Unknown = 0,

    /// <summary>The policy does not require this control.</summary>
    NotConfigured = 1,

    /// <summary>Applied and verified.</summary>
    Enforced = 2,

    /// <summary>Some parts applied and verified; details describe what is missing.</summary>
    PartiallyEnforced = 3,

    /// <summary>Applied in audit mode: violations are logged but not blocked.</summary>
    AuditOnly = 4,

    /// <summary>The Windows edition or build on this computer cannot enforce the control.</summary>
    NotSupportedOnEdition = 5,

    /// <summary>The control could not be applied or verification failed.</summary>
    Failed = 6,

    /// <summary>The control has not been implemented in this version of the agent.</summary>
    NotImplemented = 7,

    /// <summary>An administrator lifted the control on this computer for a limited time.</summary>
    TemporarilyAllowed = 8,
}

/// <summary>Status of one control, as reported by the agent in each heartbeat.</summary>
public sealed record ControlStatus(SecurityControl Control, ControlState State, string? Details, DateTimeOffset VerifiedAtUtc);
