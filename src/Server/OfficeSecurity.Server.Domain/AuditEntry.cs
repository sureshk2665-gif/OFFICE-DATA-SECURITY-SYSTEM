namespace OfficeSecurity.Server.Domain;

/// <summary>
/// Append-only, hash-chained audit record. <see cref="Hash"/> covers every field plus
/// <see cref="PreviousHash"/>, so any modification or deletion breaks the chain.
/// </summary>
public sealed class AuditEntry
{
    public long Id { get; set; }

    public DateTimeOffset OccurredAtUtc { get; set; }

    public AuditActorType ActorType { get; set; }

    public Guid? ActorId { get; set; }

    public string? ActorName { get; set; }

    /// <summary>Dotted action code, e.g. "auth.admin.login".</summary>
    public required string Action { get; set; }

    public AuditOutcome Outcome { get; set; }

    public string? TargetType { get; set; }

    public string? TargetId { get; set; }

    public string? SourceIp { get; set; }

    /// <summary>Additional non-sensitive details. Never contains passwords, codes or tokens.</summary>
    public string? Details { get; set; }

    public required string PreviousHash { get; set; }

    public required string Hash { get; set; }
}
