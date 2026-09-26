namespace OfficeSecurity.Server.Domain;

public sealed class StaffAccount : ILockableAccount
{
    public Guid Id { get; set; }

    /// <summary>Employee code the staff member signs in with (e.g. "EMP042").</summary>
    public required string EmployeeCode { get; set; }

    public required string NormalizedEmployeeCode { get; set; }

    public required string DisplayName { get; set; }

    public string? Department { get; set; }

    public AccountStatus Status { get; set; }

    /// <summary>PBKDF2 hash; never the password itself. Null until the staff member sets a password.</summary>
    public string? PasswordHash { get; set; }

    public int FailedLoginCount { get; set; }

    public DateTimeOffset? LockedUntilUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }

    public DateTimeOffset? LastLoginAtUtc { get; set; }
}
