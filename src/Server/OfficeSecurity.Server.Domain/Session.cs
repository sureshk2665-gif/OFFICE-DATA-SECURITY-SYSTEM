namespace OfficeSecurity.Server.Domain;

/// <summary>A signed-in session. The bearer token is random; only its SHA-256 hash is stored.</summary>
public sealed class Session
{
    public Guid Id { get; set; }

    public required string TokenHash { get; set; }

    public PrincipalType PrincipalType { get; set; }

    public Guid PrincipalId { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public DateTimeOffset LastSeenAtUtc { get; set; }

    public DateTimeOffset ExpiresAtUtc { get; set; }

    public DateTimeOffset? EndedAtUtc { get; set; }

    public string? EndReason { get; set; }

    public string? SourceIp { get; set; }
}
