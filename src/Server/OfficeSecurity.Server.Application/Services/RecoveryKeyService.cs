using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>
/// BitLocker recovery keys reported by computers. Stored encrypted; only a super administrator can reveal one,
/// and every reveal is written to the audit log.
/// </summary>
public sealed partial class RecoveryKeyService(IServerDbContext db, AuditLog audit, ISecretProtector protector, TimeProvider clock)
{
    public const int MaxKeysPerComputer = 26;

    /// <summary>Stores the computer's current keys (called with the inventory report).</summary>
    public async Task StoreAsync(Guid computerId, IReadOnlyList<RecoveryKeyReport> reported, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(reported);
        var now = clock.GetUtcNow();
        var valid = reported
            .Where(k => DriveRegex().IsMatch(k.Drive ?? string.Empty) && ProtectorRegex().IsMatch(k.ProtectorId ?? string.Empty) && PasswordRegex().IsMatch(k.RecoveryPassword ?? string.Empty))
            .DistinctBy(k => k.ProtectorId)
            .Take(MaxKeysPerComputer)
            .ToList();
        var existing = await db.RecoveryKeys.Where(k => k.ComputerId == computerId).ToListAsync(ct).ConfigureAwait(false);
        var added = 0;
        foreach (var key in valid)
        {
            var row = existing.FirstOrDefault(e => e.ProtectorId == key.ProtectorId);
            if (row is null)
            {
                db.RecoveryKeys.Add(new BitLockerRecoveryKey
                {
                    ComputerId = computerId,
                    Drive = key.Drive,
                    ProtectorId = key.ProtectorId,
                    ProtectedPassword = protector.Protect(Encoding.UTF8.GetBytes(key.RecoveryPassword)),
                    FirstReportedUtc = now,
                    LastReportedUtc = now,
                });
                added++;
            }
            else
            {
                row.Drive = key.Drive;
                row.ProtectedPassword = protector.Protect(Encoding.UTF8.GetBytes(key.RecoveryPassword));
                row.LastReportedUtc = now;
            }
        }

        // Keys the computer no longer has are kept: an old recovery key can still be needed for a backup image.
        if (added > 0)
        {
            await audit.RecordAndSaveAsync(RequestContext.System, new AuditRecord("bitlocker.recovery-key.stored", TargetType: "Computer", TargetId: computerId.ToString(),
                Details: $"{added} new recovery key(s)", ActorTypeOverride: AuditActorType.Computer, ActorIdOverride: computerId), ct).ConfigureAwait(false);
        }
        else
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
    }

    public async Task<Result<IReadOnlyList<RecoveryKeyResponse>>> ListAsync(Guid computerId, CancellationToken ct = default)
    {
        if (!await db.Computers.AnyAsync(c => c.Id == computerId, ct).ConfigureAwait(false))
        {
            return ServiceError.NotFound("Computer not found.");
        }

        var rows = await db.RecoveryKeys.AsNoTracking().Where(k => k.ComputerId == computerId).OrderBy(k => k.Drive).ThenByDescending(k => k.LastReportedUtc)
            .Select(k => new RecoveryKeyResponse(k.Id, k.Drive, k.ProtectorId, k.FirstReportedUtc, k.LastReportedUtc)).ToListAsync(ct).ConfigureAwait(false);
        return rows;
    }

    public async Task<Result<RecoveryKeyRevealResponse>> RevealAsync(Guid computerId, long keyId, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var key = await db.RecoveryKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == keyId && k.ComputerId == computerId, ct).ConfigureAwait(false);
        if (key is null)
        {
            return ServiceError.NotFound("Recovery key not found.");
        }

        var hostname = await db.Computers.AsNoTracking().Where(c => c.Id == computerId).Select(c => c.Hostname).FirstAsync(ct).ConfigureAwait(false);
        await audit.RecordAndSaveAsync(context, new AuditRecord("bitlocker.recovery-key.reveal", TargetType: "Computer", TargetId: computerId.ToString(),
            Details: $"{hostname} drive {key.Drive}, protector {key.ProtectorId}"), ct).ConfigureAwait(false);
        return new RecoveryKeyRevealResponse(key.Id, key.Drive, Encoding.UTF8.GetString(protector.Unprotect(key.ProtectedPassword)));
    }

    [GeneratedRegex(@"^[A-Za-z]:$")]
    private static partial Regex DriveRegex();

    [GeneratedRegex(@"^\{[0-9A-Fa-f-]{36}\}$")]
    private static partial Regex ProtectorRegex();

    // BitLocker recovery passwords: 8 groups of 6 digits.
    [GeneratedRegex(@"^\d{6}(-\d{6}){7}$")]
    private static partial Regex PasswordRegex();
}
