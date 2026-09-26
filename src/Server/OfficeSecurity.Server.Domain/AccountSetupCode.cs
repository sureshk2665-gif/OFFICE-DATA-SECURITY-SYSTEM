namespace OfficeSecurity.Server.Domain;

/// <summary>
/// One-time code an administrator hands to a person so they can set their own password.
/// Only a hash of the code is stored.
/// </summary>
public sealed class AccountSetupCode
{
    public Guid Id { get; set; }

    public PrincipalType AccountType { get; set; }

    public Guid AccountId { get; set; }

    public required string CodeHash { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset ExpiresAtUtc { get; set; }

    public DateTimeOffset? UsedAtUtc { get; set; }

    public DateTimeOffset? RevokedAtUtc { get; set; }

    public Guid? CreatedByAdminId { get; set; }

    public bool IsUsableAt(DateTimeOffset nowUtc) => UsedAtUtc is null && RevokedAtUtc is null && nowUtc < ExpiresAtUtc;
}
