using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>
/// Temporary, per-computer exceptions to a security control ("allow USB drives on PC-07 until 16:00").
/// Every change raises the computer's policy version so the agent receives it at its next check-in.
/// </summary>
public sealed class ExemptionService(IServerDbContext db, AuditLog audit, TimeProvider clock)
{
    public async Task<Result<IReadOnlyList<ExemptionResponse>>> ListAsync(Guid computerId, CancellationToken ct = default)
    {
        if (!await db.Computers.AnyAsync(c => c.Id == computerId, ct).ConfigureAwait(false))
        {
            return ServiceError.NotFound("Computer not found.");
        }

        var rows = await db.Exemptions.AsNoTracking().Where(x => x.ComputerId == computerId)
            .OrderByDescending(x => x.CreatedAtUtc).Take(50).ToListAsync(ct).ConfigureAwait(false);
        var adminIds = rows.Select(r => r.CreatedByAdminId).Distinct().ToList();
        var admins = await db.Admins.AsNoTracking().Where(a => adminIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.DisplayName, ct).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        return rows.Select(r => ToResponse(r, admins.GetValueOrDefault(r.CreatedByAdminId), now)).ToList();
    }

    public async Task<Result<ExemptionResponse>> CreateAsync(Guid computerId, CreateExemptionRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var computer = await db.Computers.FirstOrDefaultAsync(c => c.Id == computerId, ct).ConfigureAwait(false);
        if (computer is null)
        {
            return ServiceError.NotFound("Computer not found.");
        }

        if (computer.Status != ComputerStatus.Trusted)
        {
            return ServiceError.Validation("Exceptions can only be given to approved computers.");
        }

        if (!Enum.TryParse<SecurityControl>(request.Control, out var control) || !Exemptions.AllowedControls.Contains(control))
        {
            return ServiceError.Validation("This control cannot be lifted temporarily.");
        }

        var reason = request.Reason?.Trim() ?? string.Empty;
        if (reason.Length is < 3 or > 500 || reason.Any(char.IsControl))
        {
            return ServiceError.Validation("Give a reason (3–500 characters). It is recorded in the audit log.");
        }

        if (request.DurationMinutes is < Exemptions.MinMinutes or > Exemptions.MaxMinutes)
        {
            return ServiceError.Validation("The duration must be between 5 minutes and 30 days.");
        }

        var now = clock.GetUtcNow();
        var exemption = new ControlExemption
        {
            Id = Guid.NewGuid(),
            ComputerId = computerId,
            Control = control.ToString(),
            Reason = reason,
            StartsAtUtc = now,
            ExpiresAtUtc = now.AddMinutes(request.DurationMinutes),
            CreatedAtUtc = now,
            CreatedByAdminId = context.Principal?.Id ?? Guid.Empty,
        };
        db.Exemptions.Add(exemption);
        computer.PolicyVersion++;
        await audit.RecordAndSaveAsync(context, new AuditRecord("computer.exemption.create", TargetType: "Computer", TargetId: computerId.ToString(),
            Details: $"{computer.Hostname}: {control} lifted until {exemption.ExpiresAtUtc:u} — {reason}"), ct).ConfigureAwait(false);
        return ToResponse(exemption, context.Principal?.DisplayName, now);
    }

    public async Task<Result<Done>> RevokeAsync(Guid computerId, Guid exemptionId, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var exemption = await db.Exemptions.FirstOrDefaultAsync(x => x.Id == exemptionId && x.ComputerId == computerId, ct).ConfigureAwait(false);
        var computer = await db.Computers.FirstOrDefaultAsync(c => c.Id == computerId, ct).ConfigureAwait(false);
        if (exemption is null || computer is null)
        {
            return ServiceError.NotFound("Exception not found.");
        }

        var now = clock.GetUtcNow();
        if (exemption.RevokedAtUtc is not null || exemption.ExpiresAtUtc <= now)
        {
            return ServiceError.Conflict("This exception has already ended.");
        }

        exemption.RevokedAtUtc = now;
        exemption.RevokedByAdminId = context.Principal?.Id;
        computer.PolicyVersion++;
        await audit.RecordAndSaveAsync(context, new AuditRecord("computer.exemption.revoke", TargetType: "Computer", TargetId: computerId.ToString(),
            Details: $"{computer.Hostname}: {exemption.Control} exception ended early"), ct).ConfigureAwait(false);
        return Done.Value;
    }

    /// <summary>The exceptions to include in the computer's signed policy (not revoked, not yet expired).</summary>
    public async Task<IReadOnlyList<PolicyExemption>> ForPolicyAsync(Guid computerId, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var rows = await db.Exemptions.AsNoTracking().Where(x => x.ComputerId == computerId && x.RevokedAtUtc == null)
            .ToListAsync(ct).ConfigureAwait(false);
        return rows.Where(x => x.ExpiresAtUtc > now)
            .Select(x => new PolicyExemption(x.Id, Enum.Parse<SecurityControl>(x.Control), x.Reason, x.StartsAtUtc, x.ExpiresAtUtc))
            .ToList();
    }

    private static ExemptionResponse ToResponse(ControlExemption x, string? createdBy, DateTimeOffset now) => new(
        x.Id, x.ComputerId, x.Control, x.Reason, x.StartsAtUtc, x.ExpiresAtUtc, x.CreatedAtUtc, createdBy,
        x.RevokedAtUtc is null && x.StartsAtUtc <= now && x.ExpiresAtUtc > now, x.RevokedAtUtc);
}
