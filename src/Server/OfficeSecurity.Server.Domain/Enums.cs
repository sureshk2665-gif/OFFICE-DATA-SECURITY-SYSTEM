namespace OfficeSecurity.Server.Domain;

// Enum values are persisted as text; names must not be changed once released.

public enum AdminRole
{
    /// <summary>Full access, including managing other administrator accounts.</summary>
    SuperAdmin,

    /// <summary>Manages computers, staff, policies and requests; cannot manage administrators.</summary>
    Admin,

    /// <summary>Read-only access to status, alerts, audit logs and reports.</summary>
    Auditor,
}

public enum AccountStatus
{
    /// <summary>Created, waiting for the owner to set a password (and, for admins, two-step verification).</summary>
    PendingActivation,
    Active,
    Disabled,
}

public enum PrincipalType
{
    Admin,
    Staff,
}

public enum AuditActorType
{
    System,
    Anonymous,
    Admin,
    Staff,
    Computer,
}

public enum AuditOutcome
{
    Success,
    Failure,
}

public enum ComputerStatus
{
    /// <summary>Agent enrolled with a valid code; waiting for an administrator to approve it.</summary>
    PendingApproval,

    /// <summary>Approved: holds a client certificate and may talk to the server.</summary>
    Trusted,

    Rejected,

    /// <summary>Removed from management; its certificate is no longer accepted.</summary>
    Retired,
}
