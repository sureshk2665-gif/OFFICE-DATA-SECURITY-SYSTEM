using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Serialises writes to the audit chain. Registered as a singleton (one server process owns the database).</summary>
public sealed class AuditChainLock : IDisposable
{
    internal SemaphoreSlim Semaphore { get; } = new(1, 1);

    public void Dispose() => Semaphore.Dispose();
}

public sealed record AuditRecord(
    string Action,
    AuditOutcome Outcome = AuditOutcome.Success,
    string? TargetType = null,
    string? TargetId = null,
    string? Details = null,
    AuditActorType? ActorTypeOverride = null,
    Guid? ActorIdOverride = null,
    string? ActorNameOverride = null);

/// <summary>
/// Writes audit entries. <see cref="RecordAndSaveAsync"/> also saves all other pending changes in the
/// same unit of work, so an action and its audit record are committed together.
/// </summary>
public sealed class AuditLog(IServerDbContext db, AuditChainLock chainLock, TimeProvider clock)
{
    public async Task RecordAndSaveAsync(RequestContext context, AuditRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(record);

        await chainLock.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previousHash = await db.AuditEntries
                .OrderByDescending(e => e.Id)
                .Select(e => e.Hash)
                .FirstOrDefaultAsync(cancellationToken)
                .ConfigureAwait(false) ?? AuditChain.GenesisHash;

            var principal = context.Principal;
            var entry = new AuditEntry
            {
                OccurredAtUtc = clock.GetUtcNow(),
                ActorType = record.ActorTypeOverride ?? principal?.Type switch
                {
                    PrincipalType.Admin => AuditActorType.Admin,
                    PrincipalType.Staff => AuditActorType.Staff,
                    _ => context.SourceIp is null ? AuditActorType.System : AuditActorType.Anonymous,
                },
                ActorId = record.ActorIdOverride ?? principal?.Id,
                ActorName = record.ActorNameOverride ?? principal?.LoginName,
                Action = record.Action,
                Outcome = record.Outcome,
                TargetType = record.TargetType,
                TargetId = record.TargetId,
                SourceIp = context.SourceIp,
                Details = record.Details,
                PreviousHash = previousHash,
                Hash = string.Empty,
            };
            entry.Hash = AuditChain.ComputeHash(entry);

            db.AuditEntries.Add(entry);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            chainLock.Semaphore.Release();
        }
    }

    public async Task<PagedResult<AuditEntryResponse>> ListAsync(
        int page, int pageSize, string? search, DateTimeOffset? fromUtc, DateTimeOffset? toUtc, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = db.AuditEntries.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = Paging.LikePattern(search);
            query = query.Where(e => EF.Functions.Like(e.Action, pattern, Paging.LikeEscape) ||
                                     (e.ActorName != null && EF.Functions.Like(e.ActorName, pattern, Paging.LikeEscape)) ||
                                     (e.TargetId != null && EF.Functions.Like(e.TargetId, pattern, Paging.LikeEscape)) ||
                                     (e.Details != null && EF.Functions.Like(e.Details, pattern, Paging.LikeEscape)));
        }

        if (fromUtc is { } from)
        {
            var fromUniversal = from.ToUniversalTime();
            query = query.Where(e => e.OccurredAtUtc >= fromUniversal);
        }

        if (toUtc is { } to)
        {
            var toUniversal = to.ToUniversalTime();
            query = query.Where(e => e.OccurredAtUtc < toUniversal);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(e => e.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var items = rows.Select(e => new AuditEntryResponse(
            e.Id, e.OccurredAtUtc, e.ActorType.ToString(), e.ActorName, e.Action, e.Outcome.ToString(),
            e.TargetType, e.TargetId, e.SourceIp, e.Details)).ToList();
        return new PagedResult<AuditEntryResponse>(items, page, pageSize, total);
    }

    /// <summary>Recomputes the whole chain. Detects modified, inserted or removed entries (except removal of the newest entries).</summary>
    public async Task<AuditVerificationResponse> VerifyAsync(CancellationToken cancellationToken = default)
    {
        var expectedPrevious = AuditChain.GenesisHash;
        long checkedCount = 0;

        await foreach (var entry in db.AuditEntries.AsNoTracking().OrderBy(e => e.Id).AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            checkedCount++;
            if (!string.Equals(entry.PreviousHash, expectedPrevious, StringComparison.Ordinal) ||
                !string.Equals(entry.Hash, AuditChain.ComputeHash(entry), StringComparison.Ordinal))
            {
                return new AuditVerificationResponse(false, checkedCount, entry.Id,
                    $"Audit entry {entry.Id} does not match the chain: the audit log has been altered.");
            }

            expectedPrevious = entry.Hash;
        }

        return new AuditVerificationResponse(true, checkedCount, null, $"All {checkedCount} audit entries are intact.");
    }
}

internal static class Paging
{
    public const int MaxPageSize = 200;

    public const string LikeEscape = "\\";

    public static (int Page, int PageSize) Normalize(int page, int pageSize) =>
        (Math.Max(1, page), Math.Clamp(pageSize <= 0 ? 50 : pageSize, 1, MaxPageSize));

    /// <summary>Case-insensitive "contains" pattern for SQL LIKE with wildcards in the input escaped.</summary>
    public static string LikePattern(string term) =>
        "%" + term.Trim().Replace(LikeEscape, LikeEscape + LikeEscape, StringComparison.Ordinal)
            .Replace("%", LikeEscape + "%", StringComparison.Ordinal)
            .Replace("_", LikeEscape + "_", StringComparison.Ordinal) + "%";
}
