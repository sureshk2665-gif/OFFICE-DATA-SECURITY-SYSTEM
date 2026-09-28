using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Lets only one alert evaluation run at a time (singleton).</summary>
public sealed class AlertEngineLock : IDisposable
{
    internal SemaphoreSlim Semaphore { get; } = new(1, 1);

    public void Dispose() => Semaphore.Dispose();
}

/// <summary>
/// Turns security events and computer state into alerts. Run regularly by the server (every 30 seconds); reads
/// the events received since the previous run, so events from agents and from the server itself are treated
/// the same way.
/// </summary>
public sealed class AlertEngine(IServerDbContext db, AuditLog audit, AlertEngineLock gate, TimeProvider clock)
{
    public const string SystemName = "System";
    public const string LastEventKey = "alerts.last-event-id";
    public const string AuditVerifiedKey = "alerts.audit-verified-at";
    public const int MaxEventsPerRun = 5000;
    public static readonly TimeSpan AuditCheckInterval = TimeSpan.FromHours(6);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly Dictionary<(string Rule, Guid? Computer, string Subject), Alert?> _open = [];
    private Dictionary<string, AlertRuleSetting> _settings = [];
    private Dictionary<Guid, string> _hostnames = [];

    /// <summary>One evaluation: new events, then the state rules. Returns the number of alerts created.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct = default)
    {
        await gate.Semaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _open.Clear();
            _settings = await db.AlertRules.AsNoTracking().ToDictionaryAsync(r => r.Code, ct).ConfigureAwait(false);
            _hostnames = await db.Computers.AsNoTracking().ToDictionaryAsync(c => c.Id, c => c.Hostname, ct).ConfigureAwait(false);
            var created = await ProcessEventsAsync(ct).ConfigureAwait(false);
            created += await EvaluateStateAsync(ct).ConfigureAwait(false);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return created;
        }
        finally
        {
            gate.Semaphore.Release();
        }
    }

    // ---------------------------------------------------------------- event rules

    private async Task<int> ProcessEventsAsync(CancellationToken ct)
    {
        var mark = await db.Settings.FirstOrDefaultAsync(s => s.Key == LastEventKey, ct).ConfigureAwait(false);
        if (mark is null)
        {
            // First run on this database: start with the events that arrive from now on, so an existing
            // installation is not flooded with alerts for old events.
            var max = await db.SecurityEvents.MaxAsync(e => (long?)e.Id, ct).ConfigureAwait(false) ?? 0;
            db.Settings.Add(new SystemSetting { Key = LastEventKey, Value = max.ToString(CultureInfo.InvariantCulture) });
            return 0;
        }

        var after = long.Parse(mark.Value, CultureInfo.InvariantCulture);
        var events = await db.SecurityEvents.AsNoTracking().Where(e => e.Id > after).OrderBy(e => e.Id).Take(MaxEventsPerRun)
            .ToListAsync(ct).ConfigureAwait(false);
        var created = 0;
        foreach (var e in events)
        {
            foreach (var rule in AlertRules.All.Where(r => r.Kind == AlertRuleKind.Event && Applies(r, e)))
            {
                var setting = Setting(rule);
                if (setting.Enabled && await RecordEventAsync(rule, setting, e, ct).ConfigureAwait(false))
                {
                    created++;
                }
            }
        }

        if (events.Count > 0)
        {
            mark.Value = events[^1].Id.ToString(CultureInfo.InvariantCulture);
        }

        return created;
    }

    private static bool Applies(AlertRuleDefinition rule, SecurityEvent e) =>
        rule.EventTypes!.Any(t => t.ToString() == e.EventType) && (rule.Matches?.Invoke(e) ?? true);

    /// <summary>Adds the event to the open alert, or opens one when the threshold is reached. True when opened.</summary>
    private async Task<bool> RecordEventAsync(AlertRuleDefinition rule, AlertRuleSetting setting, SecurityEvent e, CancellationToken ct)
    {
        var existing = await FindOpenAsync(rule.Code, e.ComputerId, string.Empty, ct).ConfigureAwait(false);
        if (existing is not null)
        {
            existing.EventCount++;
            existing.LastEventId = e.Id;
            existing.LastSeenUtc = Max(existing.LastSeenUtc, e.OccurredAtUtc);
            existing.Details = e.Details;
            return false;
        }

        var count = 1;
        var firstId = e.Id;
        var firstSeen = e.OccurredAtUtc;
        if (setting.Threshold > 1)
        {
            // Count this computer's matching events in the window, but not those already covered by an alert
            // an administrator has resolved.
            var from = e.OccurredAtUtc - TimeSpan.FromMinutes(Math.Max(1, setting.WindowMinutes));
            var resolvedAt = await db.Alerts.AsNoTracking()
                .Where(a => a.RuleCode == rule.Code && a.ComputerId == e.ComputerId && a.Status == AlertStatus.Resolved)
                .MaxAsync(a => a.LastEventId, ct).ConfigureAwait(false) ?? 0;
            var types = rule.EventTypes!.Select(t => t.ToString()).ToList();
            var recent = (await db.SecurityEvents.AsNoTracking()
                    .Where(x => x.ComputerId == e.ComputerId && types.Contains(x.EventType) && x.Id <= e.Id && x.Id > resolvedAt && x.OccurredAtUtc >= from)
                    .ToListAsync(ct).ConfigureAwait(false))
                .Where(x => rule.Matches?.Invoke(x) ?? true)
                .ToList();
            if (recent.Count < setting.Threshold)
            {
                return false;
            }

            count = recent.Count;
            firstId = recent.Min(x => x.Id);
            firstSeen = recent.Min(x => x.OccurredAtUtc);
        }

        Open(rule, setting, e.ComputerId, string.Empty, rule.Title!(Hostname(e.ComputerId)), e.Details, count, firstSeen, e.OccurredAtUtc, firstId, e.Id);
        return true;
    }

    // ---------------------------------------------------------------- state rules

    private async Task<int> EvaluateStateAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var created = 0;
        var computers = await db.Computers.AsNoTracking()
            .Where(c => c.Status == ComputerStatus.Trusted || c.Status == ComputerStatus.PendingApproval)
            .ToListAsync(ct).ConfigureAwait(false);

        // Computer not reporting (and not shut down normally).
        if (Rule(AlertRules.ComputerNotReporting, out var rule, out var setting))
        {
            var limit = TimeSpan.FromMinutes(Math.Max(5, setting.Threshold));
            var lifecycle = new[] { nameof(SecurityEventType.AgentStarted), nameof(SecurityEventType.AgentStoppedOrUnavailable) };
            foreach (var c in computers.Where(c => c.Status == ComputerStatus.Trusted && c.LastSeenAtUtc is not null))
            {
                var silent = now - c.LastSeenAtUtc!.Value;
                var problem = false;
                if (silent > limit)
                {
                    var last = await db.SecurityEvents.AsNoTracking().Where(e => e.ComputerId == c.Id && lifecycle.Contains(e.EventType))
                        .OrderByDescending(e => e.Id).FirstOrDefaultAsync(ct).ConfigureAwait(false);
                    var switchedOff = last is { EventType: nameof(SecurityEventType.AgentStoppedOrUnavailable), Severity: EventSeverities.Information };
                    problem = !switchedOff;
                }

                created += await SetStateAsync(rule, setting, c.Id, string.Empty, problem,
                    $"{c.Hostname} is not reporting",
                    string.Create(CultureInfo.InvariantCulture, $"No contact for {(int)silent.TotalMinutes} minutes, and it was not shut down normally. ")
                    + "The security agent may have been stopped, blocked from the network or removed, or the computer lost power. Until it reports again, its protections cannot be checked.",
                    "The computer is reporting again.", ct).ConfigureAwait(false);
            }
        }

        // A required protection is not working.
        if (Rule(AlertRules.ProtectionFailed, out rule, out setting))
        {
            foreach (var c in computers.Where(c => c.Status == ComputerStatus.Trusted))
            {
                var failed = c.ControlStatusJson is null
                    ? []
                    : (JsonSerializer.Deserialize<List<ControlStatus>>(c.ControlStatusJson, Json) ?? []).Where(s => s.State == ControlState.Failed).ToList();
                created += await SetStateAsync(rule, setting, c.Id, string.Empty, failed.Count > 0,
                    $"Protection not working on {c.Hostname}",
                    string.Join(" | ", failed.Select(f => $"{f.Control}: {f.Details}")),
                    "All protections are working again.", ct).ConfigureAwait(false);
            }
        }

        // Computers waiting for approval.
        if (Rule(AlertRules.ComputerWaiting, out rule, out setting))
        {
            foreach (var c in computers)
            {
                created += await SetStateAsync(rule, setting, c.Id, string.Empty, c.Status == ComputerStatus.PendingApproval,
                    $"{c.Hostname} is waiting for approval",
                    "Approve it on the Computers page only if you recognise it; otherwise reject it.",
                    "The computer was approved or rejected.", ct).ConfigureAwait(false);
            }

            // A waiting computer that was rejected or removed no longer appears above.
            foreach (var stale in await db.Alerts.Where(a => a.RuleCode == AlertRules.ComputerWaiting && a.Status != AlertStatus.Resolved).ToListAsync(ct).ConfigureAwait(false))
            {
                if (!computers.Any(c => c.Id == stale.ComputerId && c.Status == ComputerStatus.PendingApproval))
                {
                    Resolve(stale, SystemName, "The computer was approved or rejected.", now);
                }
            }
        }

        if (Rule(AlertRules.SystemFailedSignIns, out rule, out setting))
        {
            created += await FailedSystemSignInsAsync(rule, setting, now, ct).ConfigureAwait(false);
        }

        if (Rule(AlertRules.AuditIntegrity, out rule, out setting))
        {
            created += await CheckAuditAsync(rule, setting, now, ct).ConfigureAwait(false);
        }

        return created;
    }

    private async Task<int> FailedSystemSignInsAsync(AlertRuleDefinition rule, AlertRuleSetting setting, DateTimeOffset now, CancellationToken ct)
    {
        var from = now - TimeSpan.FromMinutes(Math.Max(1, setting.WindowMinutes));
        var failures = await db.AuditEntries.AsNoTracking()
            .Where(e => e.Outcome == AuditOutcome.Failure && e.OccurredAtUtc >= from
                        && (e.Action == "auth.admin.login" || e.Action == "auth.staff.login" || e.Action == "auth.admin.activate" || e.Action == "auth.staff.activate"))
            .Select(e => new { e.Id, e.ActorName, e.Action, e.OccurredAtUtc, e.SourceIp })
            .ToListAsync(ct).ConfigureAwait(false);
        var created = 0;
        foreach (var group in failures.GroupBy(f => (f.ActorName ?? "(no name)").Trim().ToUpperInvariant()))
        {
            var subject = "account:" + group.Key;
            // Failures already covered by a resolved alert do not count again.
            var resolvedUpTo = await db.Alerts.AsNoTracking()
                .Where(a => a.RuleCode == rule.Code && a.Subject == subject && a.Status == AlertStatus.Resolved)
                .MaxAsync(a => a.LastEventId, ct).ConfigureAwait(false) ?? 0;
            var counted = group.Where(f => f.Id > resolvedUpTo).OrderBy(f => f.Id).ToList();
            var existing = await FindOpenAsync(rule.Code, null, subject, ct).ConfigureAwait(false);
            var name = group.First().ActorName ?? "(no name)";
            var who = group.First().Action.StartsWith("auth.staff", StringComparison.Ordinal) ? "staff app" : "dashboard";
            var sources = string.Join(", ", counted.Select(f => f.SourceIp).OfType<string>().Distinct());
            var details = string.Create(CultureInfo.InvariantCulture,
                $"{counted.Count} failed sign-ins to the {who} for the account name '{name}' in the last {setting.WindowMinutes} minutes{(sources.Length > 0 ? $" (from {sources})" : string.Empty)}. After 5 wrong attempts the account is locked for 15 minutes.");
            if (existing is not null)
            {
                var newer = counted.Where(f => f.Id > (existing.LastEventId ?? 0)).ToList();
                if (newer.Count > 0)
                {
                    existing.EventCount += newer.Count;
                    existing.LastEventId = newer[^1].Id;
                    existing.LastSeenUtc = newer[^1].OccurredAtUtc;
                    existing.Details = details;
                }
            }
            else if (counted.Count >= setting.Threshold)
            {
                Open(rule, setting, null, subject, $"Repeated failed sign-ins for '{name}'", details, counted.Count,
                    counted[0].OccurredAtUtc, counted[^1].OccurredAtUtc, counted[0].Id, counted[^1].Id);
                created++;
            }
        }

        return created;
    }

    private async Task<int> CheckAuditAsync(AlertRuleDefinition rule, AlertRuleSetting setting, DateTimeOffset now, CancellationToken ct)
    {
        var last = await db.Settings.FirstOrDefaultAsync(s => s.Key == AuditVerifiedKey, ct).ConfigureAwait(false);
        if (last is not null && DateTimeOffset.TryParse(last.Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at) && now - at < AuditCheckInterval)
        {
            return 0;
        }

        var result = await audit.VerifyAsync(ct).ConfigureAwait(false);
        if (last is null)
        {
            db.Settings.Add(new SystemSetting { Key = AuditVerifiedKey, Value = now.ToString("O", CultureInfo.InvariantCulture) });
        }
        else
        {
            last.Value = now.ToString("O", CultureInfo.InvariantCulture);
        }

        // Once broken, the chain stays broken: an administrator resolves the alert after investigating, and
        // it is not raised again for the same broken entry.
        if (result.IsIntact)
        {
            return 0;
        }

        var subject = "entry:" + (result.FirstBrokenEntryId?.ToString(CultureInfo.InvariantCulture) ?? "?");
        if (await db.Alerts.AnyAsync(a => a.RuleCode == rule.Code && a.Subject == subject, ct).ConfigureAwait(false))
        {
            return 0;
        }

        Open(rule, setting, null, subject, "The audit log was altered", result.Message, 1, now, now, null, null);
        return 1;
    }

    /// <summary>Opens, updates or (when the problem is gone) automatically resolves a state alert.</summary>
    private async Task<int> SetStateAsync(AlertRuleDefinition rule, AlertRuleSetting setting, Guid? computerId, string subject, bool problem,
        string title, string details, string resolvedNote, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var existing = await FindOpenAsync(rule.Code, computerId, subject, ct).ConfigureAwait(false);
        if (!problem)
        {
            if (existing is not null)
            {
                Resolve(existing, SystemName, resolvedNote, now);
                _open[(rule.Code, computerId, subject)] = null;
            }

            return 0;
        }

        if (existing is not null)
        {
            existing.Details = details;
            existing.LastSeenUtc = now;
            return 0;
        }

        Open(rule, setting, computerId, subject, title, details, 1, now, now, null, null);
        return 1;
    }

    // ---------------------------------------------------------------- helpers

    private void Open(AlertRuleDefinition rule, AlertRuleSetting setting, Guid? computerId, string subject, string title, string? details, int count,
        DateTimeOffset firstSeen, DateTimeOffset lastSeen, long? firstEventId, long? lastEventId)
    {
        var alert = new Alert
        {
            Id = Guid.NewGuid(),
            RuleCode = rule.Code,
            Severity = setting.Severity,
            ComputerId = computerId,
            Subject = subject,
            Title = Truncate(title, 300)!,
            Details = Truncate(details, 2000),
            EventCount = count,
            FirstSeenUtc = firstSeen,
            LastSeenUtc = lastSeen,
            FirstEventId = firstEventId,
            LastEventId = lastEventId,
            Status = AlertStatus.Open,
        };
        db.Alerts.Add(alert);
        _open[(rule.Code, computerId, subject)] = alert;
    }

    internal static void Resolve(Alert alert, string by, string? note, DateTimeOffset now)
    {
        alert.Status = AlertStatus.Resolved;
        alert.ResolvedBy = by;
        alert.ResolvedAtUtc = now;
        alert.ResolutionNote = Truncate(note, 1000);
    }

    private async Task<Alert?> FindOpenAsync(string rule, Guid? computerId, string subject, CancellationToken ct)
    {
        var key = (rule, computerId, subject);
        if (!_open.TryGetValue(key, out var alert))
        {
            alert = await db.Alerts.FirstOrDefaultAsync(a => a.RuleCode == rule && a.ComputerId == computerId && a.Subject == subject && a.Status != AlertStatus.Resolved, ct)
                .ConfigureAwait(false);
            _open[key] = alert;
        }

        return alert;
    }

    private bool Rule(string code, out AlertRuleDefinition rule, out AlertRuleSetting setting)
    {
        rule = AlertRules.Find(code)!;
        setting = Setting(rule);
        return setting.Enabled;
    }

    private AlertRuleSetting Setting(AlertRuleDefinition rule) => AlertRules.Effective(rule, _settings.GetValueOrDefault(rule.Code));

    private string Hostname(Guid id) => _hostnames.GetValueOrDefault(id, "an unknown computer");

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..(max - 1)] + "…";
}
