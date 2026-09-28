using System.Globalization;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Alerts for administrators: list, acknowledge, resolve, and the rule settings.</summary>
public sealed class AlertService(IServerDbContext db, AuditLog audit, TimeProvider clock)
{
    public const int MaxRuleThreshold = 10_000;
    public const int MaxWindowMinutes = 7 * 24 * 60;

    public async Task<PagedResult<AlertResponse>> ListAsync(int page, int pageSize, string? status, string? severity, Guid? computerId, string? search,
        CancellationToken ct = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = db.Alerts.AsNoTracking();
        query = status switch
        {
            AlertStatuses.Open => query.Where(a => a.Status == AlertStatus.Open),
            AlertStatuses.Acknowledged => query.Where(a => a.Status == AlertStatus.Acknowledged),
            AlertStatuses.Resolved => query.Where(a => a.Status == AlertStatus.Resolved),
            AlertStatuses.Active => query.Where(a => a.Status != AlertStatus.Resolved),
            _ => query,
        };
        if (severity is EventSeverities.Information or EventSeverities.Warning or EventSeverities.Critical)
        {
            query = query.Where(a => a.Severity == severity);
        }

        if (computerId is { } cid)
        {
            query = query.Where(a => a.ComputerId == cid);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = Paging.LikePattern(search);
            query = query.Where(a => EF.Functions.Like(a.Title, pattern, Paging.LikeEscape) || (a.Details != null && EF.Functions.Like(a.Details, pattern, Paging.LikeEscape)));
        }

        var total = await query.CountAsync(ct).ConfigureAwait(false);
        var rows = await query.OrderByDescending(a => a.LastSeenUtc).ThenBy(a => a.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct).ConfigureAwait(false);
        var names = await HostnamesAsync(rows.Select(r => r.ComputerId), ct).ConfigureAwait(false);
        return new PagedResult<AlertResponse>(rows.Select(r => ToResponse(r, names)).ToList(), page, pageSize, total);
    }

    public async Task<AlertSummaryResponse> SummaryAsync(CancellationToken ct = default)
    {
        var active = await db.Alerts.AsNoTracking().Where(a => a.Status != AlertStatus.Resolved)
            .Select(a => new { a.Status, a.Severity, a.LastSeenUtc }).ToListAsync(ct).ConfigureAwait(false);
        return new AlertSummaryResponse(
            active.Count(a => a.Status == AlertStatus.Open),
            active.Count(a => a.Status == AlertStatus.Open && a.Severity == EventSeverities.Critical),
            active.Count(a => a.Status == AlertStatus.Acknowledged),
            active.Count == 0 ? null : active.Max(a => a.LastSeenUtc));
    }

    public async Task<Result<AlertResponse>> AcknowledgeAsync(Guid id, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id, ct).ConfigureAwait(false);
        if (alert is null)
        {
            return ServiceError.NotFound("Alert not found.");
        }

        if (alert.Status != AlertStatus.Open)
        {
            return ServiceError.Conflict(alert.Status == AlertStatus.Resolved ? "This alert is already resolved." : "This alert is already acknowledged.");
        }

        alert.Status = AlertStatus.Acknowledged;
        alert.AcknowledgedBy = context.Principal?.LoginName;
        alert.AcknowledgedAtUtc = clock.GetUtcNow();
        await audit.RecordAndSaveAsync(context, new AuditRecord("alert.acknowledge", TargetType: "Alert", TargetId: id.ToString(), Details: alert.Title), ct).ConfigureAwait(false);
        return ToResponse(alert, await HostnamesAsync([alert.ComputerId], ct).ConfigureAwait(false));
    }

    public async Task<Result<AlertResponse>> ResolveAsync(Guid id, ResolveAlertRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var note = request.Note?.Trim();
        if (note is { Length: > 1000 } || note?.Any(c => char.IsControl(c) && c is not '\r' and not '\n') == true)
        {
            return ServiceError.Validation("The note can have at most 1000 characters.");
        }

        var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id, ct).ConfigureAwait(false);
        if (alert is null)
        {
            return ServiceError.NotFound("Alert not found.");
        }

        if (alert.Status == AlertStatus.Resolved)
        {
            return ServiceError.Conflict("This alert is already resolved.");
        }

        AlertEngine.Resolve(alert, context.Principal?.LoginName ?? AlertEngine.SystemName, string.IsNullOrEmpty(note) ? null : note, clock.GetUtcNow());
        await audit.RecordAndSaveAsync(context, new AuditRecord("alert.resolve", TargetType: "Alert", TargetId: id.ToString(),
            Details: string.IsNullOrEmpty(note) ? alert.Title : $"{alert.Title} — {note}"), ct).ConfigureAwait(false);
        return ToResponse(alert, await HostnamesAsync([alert.ComputerId], ct).ConfigureAwait(false));
    }

    public async Task<IReadOnlyList<AlertRuleResponse>> ListRulesAsync(CancellationToken ct = default)
    {
        var saved = await db.AlertRules.AsNoTracking().ToDictionaryAsync(r => r.Code, ct).ConfigureAwait(false);
        return AlertRules.All.Select(r => ToResponse(r, AlertRules.Effective(r, saved.GetValueOrDefault(r.Code)))).ToList();
    }

    public async Task<Result<AlertRuleResponse>> UpdateRuleAsync(string code, UpdateAlertRuleRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        if (AlertRules.Find(code) is not { } rule)
        {
            return ServiceError.NotFound("Alert rule not found.");
        }

        if (request.Severity is not (EventSeverities.Information or EventSeverities.Warning or EventSeverities.Critical))
        {
            return ServiceError.Validation("Severity must be Information, Warning or Critical.");
        }

        var minimum = rule.Code == AlertRules.ComputerNotReporting ? 5 : 1;
        if (rule.ThresholdMeaning is not null && request.Threshold is var t && (t < minimum || t > MaxRuleThreshold))
        {
            return ServiceError.Validation(string.Create(CultureInfo.InvariantCulture, $"The number must be between {minimum} and {MaxRuleThreshold}."));
        }

        if (rule.UsesWindow && request.WindowMinutes is < 1 or > MaxWindowMinutes)
        {
            return ServiceError.Validation("The time window must be between 1 minute and 7 days.");
        }

        var setting = await db.AlertRules.FirstOrDefaultAsync(r => r.Code == code, ct).ConfigureAwait(false);
        if (setting is null)
        {
            setting = AlertRules.Effective(rule, null);
            db.AlertRules.Add(setting);
        }

        var before = Describe(rule, setting);
        setting.Enabled = request.Enabled;
        setting.Severity = request.Severity;
        if (rule.ThresholdMeaning is not null)
        {
            setting.Threshold = request.Threshold;
        }

        if (rule.UsesWindow)
        {
            setting.WindowMinutes = request.WindowMinutes;
        }

        setting.UpdatedBy = context.Principal?.LoginName;
        setting.UpdatedAtUtc = clock.GetUtcNow();
        await audit.RecordAndSaveAsync(context, new AuditRecord("alert.rule.update", TargetType: "AlertRule", TargetId: code,
            Details: $"{before} → {Describe(rule, setting)}"), ct).ConfigureAwait(false);
        return ToResponse(rule, setting);
    }

    private static string Describe(AlertRuleDefinition rule, AlertRuleSetting s) =>
        string.Create(CultureInfo.InvariantCulture,
            $"{(s.Enabled ? "on" : "off")}, {s.Severity}{(rule.ThresholdMeaning is null ? string.Empty : $", {s.Threshold} {rule.ThresholdMeaning}")}{(rule.UsesWindow ? $" in {s.WindowMinutes} min" : string.Empty)}");

    private async Task<Dictionary<Guid, string>> HostnamesAsync(IEnumerable<Guid?> ids, CancellationToken ct)
    {
        var wanted = ids.OfType<Guid>().Distinct().ToList();
        return await db.Computers.AsNoTracking().Where(c => wanted.Contains(c.Id)).ToDictionaryAsync(c => c.Id, c => c.Hostname, ct).ConfigureAwait(false);
    }

    internal static AlertResponse ToResponse(Alert a, IReadOnlyDictionary<Guid, string> hostnames) => new(
        a.Id, a.RuleCode, AlertRules.Find(a.RuleCode)?.Name ?? a.RuleCode, a.Severity, a.ComputerId,
        a.ComputerId is { } id ? hostnames.GetValueOrDefault(id) : null,
        a.Title, a.Details, a.EventCount, a.FirstSeenUtc, a.LastSeenUtc, a.Status.ToString(),
        a.AcknowledgedBy, a.AcknowledgedAtUtc, a.ResolvedBy, a.ResolvedAtUtc, a.ResolutionNote);

    private static AlertRuleResponse ToResponse(AlertRuleDefinition r, AlertRuleSetting s) =>
        new(r.Code, r.Name, r.Description, s.Enabled, s.Severity, s.Threshold, s.WindowMinutes, r.ThresholdMeaning, r.UsesWindow, s.UpdatedBy, s.UpdatedAtUtc);
}
