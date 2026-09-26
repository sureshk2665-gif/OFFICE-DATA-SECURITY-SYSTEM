using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Hash-chain computation for <see cref="AuditEntry"/>.</summary>
public static class AuditChain
{
    public static readonly string GenesisHash = new('0', 64);

    private const char Separator = '\u001f';

    public static string ComputeHash(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var canonical = string.Join(
            Separator,
            entry.PreviousHash,
            entry.OccurredAtUtc.UtcTicks.ToString(CultureInfo.InvariantCulture),
            entry.ActorType.ToString(),
            entry.ActorId?.ToString("D") ?? string.Empty,
            entry.ActorName ?? string.Empty,
            entry.Action,
            entry.Outcome.ToString(),
            entry.TargetType ?? string.Empty,
            entry.TargetId ?? string.Empty,
            entry.SourceIp ?? string.Empty,
            entry.Details ?? string.Empty);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
