namespace OfficeSecurity.Server.Domain;

public sealed class AdminAccount : ILockableAccount
{
    public Guid Id { get; set; }

    public required string Username { get; set; }

    /// <summary>Upper-invariant copy of <see cref="Username"/> used for unique, case-insensitive lookup.</summary>
    public required string NormalizedUsername { get; set; }

    public required string DisplayName { get; set; }

    public AdminRole Role { get; set; }

    public AccountStatus Status { get; set; }

    /// <summary>PBKDF2 hash; never the password itself. Null until the account is activated.</summary>
    public string? PasswordHash { get; set; }

    /// <summary>TOTP secret encrypted with the server's data-protection key.</summary>
    public byte[]? TotpSecretProtected { get; set; }

    public bool MfaEnabled { get; set; }

    /// <summary>Last accepted TOTP time step; codes at or before it are rejected (replay protection).</summary>
    public long LastTotpTimeStep { get; set; }

    public int FailedLoginCount { get; set; }

    public DateTimeOffset? LockedUntilUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }

    public DateTimeOffset? LastLoginAtUtc { get; set; }
}
