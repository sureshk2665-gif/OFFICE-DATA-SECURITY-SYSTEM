namespace OfficeSecurity.Server.Application.Common;

public sealed class SecurityOptions
{
    public const string SectionName = "Security";

    public int PasswordHashIterations { get; set; } = Security.PasswordHasher.DefaultIterations;

    /// <summary>Failed sign-in attempts (passwords, codes) before the account is locked.</summary>
    public int MaxFailedAttempts { get; set; } = 5;

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    public TimeSpan SetupCodeLifetime { get; set; } = TimeSpan.FromHours(72);

    public TimeSpan AdminSessionLifetime { get; set; } = TimeSpan.FromHours(8);

    public TimeSpan AdminSessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(30);

    public TimeSpan StaffSessionLifetime { get; set; } = TimeSpan.FromHours(12);

    public TimeSpan StaffSessionIdleTimeout { get; set; } = TimeSpan.FromHours(4);

    /// <summary>Time allowed between password check and two-step code, and for authenticator enrollment.</summary>
    public TimeSpan MfaTicketLifetime { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan MfaEnrollmentLifetime { get; set; } = TimeSpan.FromMinutes(15);

    public string TotpIssuer { get; set; } = "Office Security";
}
