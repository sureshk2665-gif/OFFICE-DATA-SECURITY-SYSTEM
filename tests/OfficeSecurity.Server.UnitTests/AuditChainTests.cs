using OfficeSecurity.Server.Application.Services;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.UnitTests;

public sealed class AuditChainTests
{
    private static AuditEntry Entry(string previous) => new()
    {
        OccurredAtUtc = new DateTimeOffset(2026, 9, 26, 8, 0, 0, TimeSpan.Zero),
        ActorType = AuditActorType.Admin,
        ActorId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
        ActorName = "admin",
        Action = "staff.create",
        Outcome = AuditOutcome.Success,
        TargetType = "Staff",
        TargetId = "abc",
        SourceIp = "192.168.1.10",
        Details = "employee code EMP01",
        PreviousHash = previous,
        Hash = string.Empty,
    };

    [Fact]
    public void Hash_is_deterministic() =>
        Assert.Equal(AuditChain.ComputeHash(Entry(AuditChain.GenesisHash)), AuditChain.ComputeHash(Entry(AuditChain.GenesisHash)));

    [Fact]
    public void Any_field_change_changes_the_hash()
    {
        var original = AuditChain.ComputeHash(Entry(AuditChain.GenesisHash));
        var variants = new Action<AuditEntry>[]
        {
            e => e.OccurredAtUtc = e.OccurredAtUtc.AddTicks(1),
            e => e.ActorType = AuditActorType.Staff,
            e => e.ActorId = Guid.Empty,
            e => e.ActorName = "someone",
            e => e.Action = "staff.delete",
            e => e.Outcome = AuditOutcome.Failure,
            e => e.TargetType = "Admin",
            e => e.TargetId = "abd",
            e => e.SourceIp = "192.168.1.11",
            e => e.Details = "employee code EMP02",
            e => e.PreviousHash = new string('1', 64),
        };

        foreach (var change in variants)
        {
            var entry = Entry(AuditChain.GenesisHash);
            change(entry);
            Assert.NotEqual(original, AuditChain.ComputeHash(entry));
        }
    }
}
