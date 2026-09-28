using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Services;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Reports;

public sealed record ReportFile(string FileName, string ContentType, byte[] Content, int RowCount);

/// <summary>
/// Reports built from the stored events, alerts, inventory and audit log, as CSV or PDF. Times are shown in the
/// server's time zone. Every export is recorded in the audit log with the file's SHA-256.
/// </summary>
public sealed class ReportService(IServerDbContext db, AuditLog audit, TimeProvider clock)
{
    public const int MaxRowsPerSection = 20_000;
    public const int MaxDays = 400;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public const string SecuritySummary = "security-summary";
    public const string Events = "events";
    public const string UsbDevices = "usb-devices";
    public const string Blocked = "blocked";
    public const string SignIns = "sign-ins";
    public const string FileAccess = "file-access";
    public const string Software = "software";
    public const string SoftwareRequests = "software-requests";
    public const string Alerts = "alerts";
    public const string Computers = "computers";
    public const string AuditLogReport = "audit-log";

    public static IReadOnlyList<ReportTypeInfo> Types { get; } =
    [
        new(SecuritySummary, "Security summary", "Totals for the period: events, alerts, blocked activity per computer, protection status, sign-ins and software. Use it weekly or monthly.", true, false),
        new(Blocked, "Blocked activity", "Every blocked USB drive or phone, blocked program, ransomware block and tampering attempt.", true, true),
        new(UsbDevices, "USB drives, phones and devices", "Devices connected, disconnected, blocked and approved, and every device each computer has seen.", true, true),
        new(SignIns, "Sign-ins", "Windows sign-ins and failed sign-ins on the computers, and sign-ins to the dashboard and staff app.", true, true),
        new(FileAccess, "Company folder file access", "Who opened, changed or deleted files in the protected company folders, and ransomware blocks.", true, true),
        new(Software, "Installed software", "Programs installed on the approved computers now, and whether each is approved.", false, true),
        new(SoftwareRequests, "Software requests and installations", "Staff requests with the decision, and installations sent to computers.", true, true),
        new(Alerts, "Alerts", "Alerts raised in the period, with who acknowledged or resolved them.", true, true),
        new(Computers, "Computers and protection status", "Every managed computer now: online, policy, and any protection that is not working.", false, false),
        new(Events, "All security events", "Every event the computers and the server recorded in the period.", true, true),
        new(AuditLogReport, "Audit log", "Every administrator and system action in the period, with the result of the integrity check.", true, false),
    ];

    private static readonly string[] BlockedTypes =
    [
        nameof(SecurityEventType.RemovableStorageBlocked), nameof(SecurityEventType.UnauthorizedUsbConnection), nameof(SecurityEventType.FileTransferBlocked),
        nameof(SecurityEventType.UnauthorizedApplicationBlocked), nameof(SecurityEventType.PolicyViolation), nameof(SecurityEventType.PolicyTamperAttempt),
        nameof(SecurityEventType.UnauthorizedSoftwareInstallAttempt),
    ];

    private static readonly string[] DeviceTypes =
    [
        nameof(SecurityEventType.DeviceConnected), nameof(SecurityEventType.DeviceDisconnected), nameof(SecurityEventType.ApprovedDeviceConnected),
        nameof(SecurityEventType.RemovableStorageBlocked), nameof(SecurityEventType.UnauthorizedUsbConnection),
    ];

    private static readonly string[] WindowsSignInTypes =
        [nameof(SecurityEventType.SuccessfulLogin), nameof(SecurityEventType.FailedLogin), nameof(SecurityEventType.Logout)];

    private static readonly string[] SystemSignInActions =
        ["auth.admin.login", "auth.staff.login", "auth.admin.logout", "auth.staff.logout", "auth.admin.activate", "auth.staff.activate"];

    /// <summary>Creates a report file for the dashboard and records the export in the audit log.</summary>
    public async Task<Result<ReportFile>> CreateAsync(string type, DateTimeOffset? from, DateTimeOffset? to, Guid? computerId, string? format,
        RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var info = Types.FirstOrDefault(t => t.Code == type);
        if (info is null)
        {
            return ServiceError.NotFound("Unknown report.");
        }

        format = (format ?? ReportFormats.Pdf).ToLowerInvariant();
        if (format is not (ReportFormats.Csv or ReportFormats.Pdf))
        {
            return ServiceError.Validation("The format must be csv or pdf.");
        }

        var end = to ?? clock.GetUtcNow();
        var start = from ?? end.AddDays(-7);
        if (start >= end || end - start > TimeSpan.FromDays(MaxDays))
        {
            return ServiceError.Validation(string.Create(CultureInfo.InvariantCulture, $"Choose a period of at most {MaxDays} days, with the start before the end."));
        }

        if (computerId is { } cid && !await db.Computers.AnyAsync(c => c.Id == cid, ct).ConfigureAwait(false))
        {
            return ServiceError.NotFound("Computer not found.");
        }

        var by = context.Principal?.DisplayName ?? AlertEngine.SystemName;
        var report = await BuildAsync(type, start, end, info.UsesComputer ? computerId : null, by, ct).ConfigureAwait(false);
        var file = Render(report, type, start, end, format);
        var hash = Convert.ToHexString(SHA256.HashData(file.Content)).ToLowerInvariant();
        await audit.RecordAndSaveAsync(context, new AuditRecord("report.export", TargetType: "Report", TargetId: type,
            Details: string.Create(CultureInfo.InvariantCulture,
                $"{info.Name}; {(info.UsesPeriod ? $"{start:u} to {end:u}; " : string.Empty)}{(computerId is null || !info.UsesComputer ? string.Empty : $"computer {computerId}; ")}{format.ToUpperInvariant()}; {file.RowCount} rows; SHA-256 {hash}")),
            ct).ConfigureAwait(false);
        return file;
    }

    public ReportFile Render(ReportDocument report, string type, DateTimeOffset from, DateTimeOffset to, string format)
    {
        ArgumentNullException.ThrowIfNull(report);
        var name = string.Create(CultureInfo.InvariantCulture, $"{type}-{Local(from, "yyyy-MM-dd")}-to-{Local(to, "yyyy-MM-dd")}.{format}");
        var rows = report.Sections.Sum(s => s.Rows.Count);
        return format == ReportFormats.Csv
            ? new ReportFile(name, "text/csv; charset=utf-8", CsvReportWriter.Write(report), rows)
            : new ReportFile(name, "application/pdf", PdfReportWriter.Write(report), rows);
    }

    public async Task<ReportDocument> BuildAsync(string type, DateTimeOffset from, DateTimeOffset to, Guid? computerId, string generatedBy, CancellationToken ct = default)
    {
        var info = Types.First(t => t.Code == type);
        var names = await db.Computers.AsNoTracking().ToDictionaryAsync(c => c.Id, c => c.Hostname, ct).ConfigureAwait(false);
        var facts = new List<KeyValuePair<string, string>>();
        if (computerId is { } cid)
        {
            facts.Add(new("Computer", names.GetValueOrDefault(cid, "?")));
        }

        var sections = type switch
        {
            SecuritySummary => await SummaryAsync(from, to, names, facts, ct).ConfigureAwait(false),
            Events => [await EventSectionAsync("Security events", null, from, to, computerId, names, ct).ConfigureAwait(false)],
            Blocked => [await EventSectionAsync("Blocked activity", BlockedTypes, from, to, computerId, names, ct, BlockedFilter).ConfigureAwait(false)],
            UsbDevices => [await EventSectionAsync("Device connections", DeviceTypes, from, to, computerId, names, ct).ConfigureAwait(false),
                await DevicesSeenAsync(computerId, names, ct).ConfigureAwait(false)],
            SignIns => [await EventSectionAsync("Windows sign-ins on the computers", WindowsSignInTypes, from, to, computerId, names, ct).ConfigureAwait(false),
                await SystemSignInsAsync(from, to, ct).ConfigureAwait(false)],
            FileAccess => [await EventSectionAsync("File access in company folders", [nameof(SecurityEventType.ProtectedFileAccess), nameof(SecurityEventType.PolicyViolation)],
                from, to, computerId, names, ct, e => e.EventType == nameof(SecurityEventType.ProtectedFileAccess) || IsRansomware(e)).ConfigureAwait(false)],
            Software => [await InstalledSoftwareAsync(computerId, names, ct).ConfigureAwait(false)],
            SoftwareRequests => await RequestsAsync(from, to, computerId, names, ct).ConfigureAwait(false),
            Alerts => [await AlertSectionAsync(from, to, computerId, names, ct).ConfigureAwait(false)],
            Computers => [await ComputersAsync(ct).ConfigureAwait(false)],
            AuditLogReport => await AuditAsync(from, to, facts, ct).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(type)),
        };

        var zone = clock.LocalTimeZone;
        var period = info.UsesPeriod
            ? $"Period: {Local(from)} to {Local(to)} (times in {zone.StandardName})"
            : $"As of {Local(clock.GetUtcNow())} (times in {zone.StandardName})";
        return new ReportDocument(info.Name, period, facts, sections,
            $"Created {Local(clock.GetUtcNow())} by {generatedBy} · Office Security System");
    }

    // ---------------------------------------------------------------- sections

    private async Task<List<ReportSection>> SummaryAsync(DateTimeOffset from, DateTimeOffset to, Dictionary<Guid, string> names,
        List<KeyValuePair<string, string>> facts, CancellationToken ct)
    {
        var events = await db.SecurityEvents.AsNoTracking().Where(e => e.OccurredAtUtc >= from && e.OccurredAtUtc < to)
            .Select(e => new { e.ComputerId, e.EventType, e.Severity, e.Details }).ToListAsync(ct).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        var computers = await db.Computers.AsNoTracking().Where(c => c.Status == ComputerStatus.Trusted).ToListAsync(ct).ConfigureAwait(false);
        var online = computers.Count(c => ComputerPresence.IsOnline(c.LastSeenAtUtc, c.HeartbeatIntervalSeconds, now));
        var openAlerts = await db.Alerts.CountAsync(a => a.Status != AlertStatus.Resolved, ct).ConfigureAwait(false);
        facts.Add(new("Approved computers now", string.Create(CultureInfo.InvariantCulture, $"{computers.Count} ({online} online, {computers.Count - online} offline)")));
        facts.Add(new("Computers with a protection not working", computers.Count(c => c.FailedControls > 0).ToString(CultureInfo.InvariantCulture)));
        facts.Add(new("Alerts not yet resolved", openAlerts.ToString(CultureInfo.InvariantCulture)));
        facts.Add(new("Security events in the period", events.Count.ToString(CultureInfo.InvariantCulture)));

        var byType = events.GroupBy(e => e.EventType).OrderBy(g => EventName(g.Key), StringComparer.Ordinal)
            .Select(g => Row(EventName(g.Key), N(g.Count(e => e.Severity == EventSeverities.Information)), N(g.Count(e => e.Severity == EventSeverities.Warning)),
                N(g.Count(e => e.Severity == EventSeverities.Critical)), N(g.Count())))
            .ToList();

        var alerts = await db.Alerts.AsNoTracking().Where(a => a.FirstSeenUtc >= from && a.FirstSeenUtc < to).ToListAsync(ct).ConfigureAwait(false);
        var alertRows = alerts.GroupBy(a => a.RuleCode).OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => Row(AlertRules.Find(g.Key)?.Name ?? g.Key, N(g.Count()), N(g.Count(a => a.Status == AlertStatus.Resolved)), N(g.Count(a => a.Status != AlertStatus.Resolved))))
            .ToList();

        var perComputer = events.GroupBy(e => e.ComputerId)
            .Select(g => new
            {
                Name = names.GetValueOrDefault(g.Key, "?"),
                Usb = g.Count(e => e.EventType is nameof(SecurityEventType.RemovableStorageBlocked) or nameof(SecurityEventType.UnauthorizedUsbConnection) or nameof(SecurityEventType.FileTransferBlocked)),
                Programs = g.Count(e => e.EventType == nameof(SecurityEventType.UnauthorizedApplicationBlocked) && e.Severity != EventSeverities.Information),
                Tamper = g.Count(e => e.EventType == nameof(SecurityEventType.PolicyTamperAttempt)),
                Ransomware = g.Count(e => e.EventType == nameof(SecurityEventType.PolicyViolation) && e.Details != null && e.Details.StartsWith("Ransomware protection blocked", StringComparison.Ordinal)),
                FailedSignIns = g.Count(e => e.EventType == nameof(SecurityEventType.FailedLogin)),
            })
            .Select(x => new { x.Name, x.Usb, x.Programs, x.Tamper, x.Ransomware, x.FailedSignIns, Total = x.Usb + x.Programs + x.Tamper + x.Ransomware + x.FailedSignIns })
            .Where(x => x.Total > 0)
            .OrderByDescending(x => x.Total).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => Row(x.Name, N(x.Usb), N(x.Programs), N(x.Ransomware), N(x.Tamper), N(x.FailedSignIns), N(x.Total)))
            .ToList();

        var signIns = await db.AuditEntries.AsNoTracking()
            .Where(e => e.OccurredAtUtc >= from && e.OccurredAtUtc < to && (e.Action == "auth.admin.login" || e.Action == "auth.staff.login"))
            .Select(e => new { e.Action, e.Outcome }).ToListAsync(ct).ConfigureAwait(false);
        var signInRows = new List<IReadOnlyList<string>>
        {
            Row("Dashboard (administrators)", N(signIns.Count(s => s.Action == "auth.admin.login" && s.Outcome == AuditOutcome.Success)),
                N(signIns.Count(s => s.Action == "auth.admin.login" && s.Outcome == AuditOutcome.Failure))),
            Row("Staff app", N(signIns.Count(s => s.Action == "auth.staff.login" && s.Outcome == AuditOutcome.Success)),
                N(signIns.Count(s => s.Action == "auth.staff.login" && s.Outcome == AuditOutcome.Failure))),
            Row("Windows (computers with sign-in records on)", N(events.Count(e => e.EventType == nameof(SecurityEventType.SuccessfulLogin))),
                N(events.Count(e => e.EventType == nameof(SecurityEventType.FailedLogin)))),
        };

        var requests = await db.SoftwareRequests.AsNoTracking().Where(r => r.CreatedAtUtc >= from && r.CreatedAtUtc < to)
            .Select(r => r.Status).ToListAsync(ct).ConfigureAwait(false);
        var jobs = await db.DeploymentJobs.AsNoTracking().Where(j => j.CreatedAtUtc >= from && j.CreatedAtUtc < to)
            .Select(j => j.Status).ToListAsync(ct).ConfigureAwait(false);
        var softwareRows = new List<IReadOnlyList<string>>
        {
            Row("Software requests from staff", N(requests.Count)),
            Row("  approved", N(requests.Count(s => s == SoftwareRequestStatus.Approved))),
            Row("  rejected", N(requests.Count(s => s == SoftwareRequestStatus.Rejected))),
            Row("  still waiting", N(requests.Count(s => s == SoftwareRequestStatus.Pending))),
            Row("Installations sent to computers", N(jobs.Count)),
            Row("  succeeded", N(jobs.Count(s => s is DeploymentStatus.Succeeded or DeploymentStatus.SucceededRebootRequired))),
            Row("  failed", N(jobs.Count(s => s == DeploymentStatus.Failed))),
            Row("Programs installed that are not approved", N(events.Count(e => e.EventType == nameof(SecurityEventType.SoftwareInstalled) && e.Severity != EventSeverities.Information))),
        };

        return
        [
            new ReportSection("Computers with blocked activity", ["Computer", "Blocked USB / phone", "Blocked programs", "Ransomware blocks", "Tampering", "Failed Windows sign-ins", "Total"], perComputer),
            new ReportSection("Alerts raised in the period", ["Alert", "Raised", "Resolved", "Not yet resolved"], alertRows),
            new ReportSection("Security events by type", ["Event", "Information", "Warning", "Critical", "Total"], byType),
            new ReportSection("Sign-ins", ["Where", "Successful", "Failed"], signInRows),
            new ReportSection("Software", ["", "Count"], softwareRows),
            await ComputersAsync(ct).ConfigureAwait(false),
        ];
    }

    private async Task<ReportSection> EventSectionAsync(string heading, string[]? types, DateTimeOffset from, DateTimeOffset to, Guid? computerId,
        Dictionary<Guid, string> names, CancellationToken ct, Func<SecurityEvent, bool>? filter = null)
    {
        var query = db.SecurityEvents.AsNoTracking().Where(e => e.OccurredAtUtc >= from && e.OccurredAtUtc < to);
        if (types is not null)
        {
            query = query.Where(e => types.Contains(e.EventType));
        }

        if (computerId is { } cid)
        {
            query = query.Where(e => e.ComputerId == cid);
        }

        var rows = (await query.OrderBy(e => e.OccurredAtUtc).ThenBy(e => e.Id).ToListAsync(ct).ConfigureAwait(false))
            .Where(e => filter?.Invoke(e) ?? true)
            .ToList();
        return Limit(new ReportSection(heading, ["Time", "Computer", "Event", "Severity", "Details"],
            rows.Select(e => Row(Local(e.OccurredAtUtc), names.GetValueOrDefault(e.ComputerId, "?"), EventName(e.EventType, e), e.Severity, e.Details)).ToList()));
    }

    private async Task<ReportSection> DevicesSeenAsync(Guid? computerId, Dictionary<Guid, string> names, CancellationToken ct)
    {
        var query = db.Devices.AsNoTracking();
        if (computerId is { } cid)
        {
            query = query.Where(d => d.ComputerId == cid);
        }

        var rows = (await query.ToListAsync(ct).ConfigureAwait(false))
            .OrderBy(d => names.GetValueOrDefault(d.ComputerId, "?"), StringComparer.OrdinalIgnoreCase).ThenBy(d => d.FirstSeenUtc)
            .Select(d => Row(names.GetValueOrDefault(d.ComputerId, "?"), d.Name, d.DeviceClass, d.Manufacturer, Local(d.FirstSeenUtc), Local(d.LastSeenUtc),
                d.IsConnected ? "yes" : "no", d.InstanceId))
            .ToList();
        return Limit(new ReportSection("Devices each computer has seen (now)", ["Computer", "Device", "Type", "Maker", "First seen", "Last seen", "Connected", "Hardware ID"], rows));
    }

    private async Task<ReportSection> SystemSignInsAsync(DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        var rows = await db.AuditEntries.AsNoTracking()
            .Where(e => e.OccurredAtUtc >= from && e.OccurredAtUtc < to && SystemSignInActions.Contains(e.Action))
            .OrderBy(e => e.Id).ToListAsync(ct).ConfigureAwait(false);
        return Limit(new ReportSection("Sign-ins to the dashboard and staff app", ["Time", "Account", "Where", "What", "Result", "Reason", "From address"],
            rows.Select(e => Row(Local(e.OccurredAtUtc), e.ActorName, e.Action.StartsWith("auth.admin", StringComparison.Ordinal) ? "Dashboard" : "Staff app",
                e.Action.EndsWith(".logout", StringComparison.Ordinal) ? "Sign-out" : e.Action.EndsWith(".activate", StringComparison.Ordinal) ? "Account set-up" : "Sign-in",
                e.Outcome == AuditOutcome.Success ? "Success" : "Failed", e.Outcome == AuditOutcome.Success ? null : e.Details, e.SourceIp)).ToList()));
    }

    private async Task<ReportSection> InstalledSoftwareAsync(Guid? computerId, Dictionary<Guid, string> names, CancellationToken ct)
    {
        var approved = await db.ApprovedSoftware.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
        var query = from i in db.InstalledSoftware.AsNoTracking()
                    join c in db.Computers.AsNoTracking() on i.ComputerId equals c.Id
                    where i.IsPresent && c.Status == ComputerStatus.Trusted
                    select i;
        if (computerId is { } cid)
        {
            query = query.Where(i => i.ComputerId == cid);
        }

        var rows = (await query.ToListAsync(ct).ConfigureAwait(false))
            .OrderBy(i => names.GetValueOrDefault(i.ComputerId, "?"), StringComparer.OrdinalIgnoreCase).ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .Select(i => Row(names.GetValueOrDefault(i.ComputerId, "?"), i.Name, i.Version, i.Publisher, i.Scope == "User" ? "One user" : "All users",
                Local(i.FirstSeenUtc), approved.Any(a => a.Matches(i.Name, i.Publisher)) ? "yes" : "NO"))
            .ToList();
        return Limit(new ReportSection("Installed programs", ["Computer", "Program", "Version", "Publisher", "Installed for", "First seen", "Approved"], rows));
    }

    private async Task<List<ReportSection>> RequestsAsync(DateTimeOffset from, DateTimeOffset to, Guid? computerId, Dictionary<Guid, string> names, CancellationToken ct)
    {
        var requests = db.SoftwareRequests.AsNoTracking().Where(r => r.CreatedAtUtc >= from && r.CreatedAtUtc < to);
        var jobs = db.DeploymentJobs.AsNoTracking().Where(j => j.CreatedAtUtc >= from && j.CreatedAtUtc < to);
        if (computerId is { } cid)
        {
            requests = requests.Where(r => r.ComputerId == cid);
            jobs = jobs.Where(j => j.ComputerId == cid);
        }

        var requestRows = await requests.OrderBy(r => r.CreatedAtUtc).ToListAsync(ct).ConfigureAwait(false);
        var jobRows = await jobs.OrderBy(j => j.CreatedAtUtc).ToListAsync(ct).ConfigureAwait(false);
        var staff = await db.Staff.AsNoTracking().ToDictionaryAsync(s => s.Id, s => $"{s.DisplayName} ({s.EmployeeCode})", ct).ConfigureAwait(false);
        var admins = await db.Admins.AsNoTracking().ToDictionaryAsync(a => a.Id, a => a.DisplayName, ct).ConfigureAwait(false);
        var packageIds = jobRows.Select(j => j.PackageId).Distinct().ToList();
        var packages = await (from p in db.SoftwarePackages.AsNoTracking()
                              join a in db.ApprovedSoftware.AsNoTracking() on p.ApprovedSoftwareId equals a.Id
                              where packageIds.Contains(p.Id)
                              select new { p.Id, a.Name, p.FileName }).ToDictionaryAsync(p => p.Id, p => $"{p.Name} ({p.FileName})", ct).ConfigureAwait(false);
        return
        [
            Limit(new ReportSection("Software requests", ["Requested", "Staff member", "Program", "Computer", "Reason", "Decision", "Decided", "By", "Note"],
                requestRows.Select(r => Row(Local(r.CreatedAtUtc), staff.GetValueOrDefault(r.StaffId, "?"), r.SoftwareName,
                    r.ComputerId is { } c ? names.GetValueOrDefault(c, "?") : null, r.Reason, r.Status.ToString(),
                    r.DecidedAtUtc is { } d ? Local(d) : null, r.ReviewedByAdminId is { } a ? admins.GetValueOrDefault(a, "?") : null, r.ReviewNote)).ToList())),
            Limit(new ReportSection("Installations sent to computers", ["Created", "Program", "Computer", "By", "Result", "Finished", "Message"],
                jobRows.Select(j => Row(Local(j.CreatedAtUtc), packages.GetValueOrDefault(j.PackageId, "?"), names.GetValueOrDefault(j.ComputerId, "?"),
                    admins.GetValueOrDefault(j.CreatedByAdminId, "?"), j.Status.ToString(), j.FinishedAtUtc is { } f ? Local(f) : null, j.Message)).ToList())),
        ];
    }

    private async Task<ReportSection> AlertSectionAsync(DateTimeOffset from, DateTimeOffset to, Guid? computerId, Dictionary<Guid, string> names, CancellationToken ct)
    {
        var query = db.Alerts.AsNoTracking().Where(a => a.FirstSeenUtc < to && a.LastSeenUtc >= from);
        if (computerId is { } cid)
        {
            query = query.Where(a => a.ComputerId == cid);
        }

        var rows = await query.OrderBy(a => a.FirstSeenUtc).ToListAsync(ct).ConfigureAwait(false);
        return Limit(new ReportSection("Alerts", ["First seen", "Last seen", "Severity", "Alert", "Computer", "Times", "Status", "Acknowledged by", "Resolved by", "Note"],
            rows.Select(a => Row(Local(a.FirstSeenUtc), Local(a.LastSeenUtc), a.Severity, a.Title, a.ComputerId is { } c ? names.GetValueOrDefault(c, "?") : null,
                N(a.EventCount), a.Status.ToString(), a.AcknowledgedBy, a.ResolvedBy, a.ResolutionNote)).ToList()));
    }

    private async Task<ReportSection> ComputersAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var computers = await db.Computers.AsNoTracking()
            .Where(c => c.Status == ComputerStatus.Trusted || c.Status == ComputerStatus.PendingApproval)
            .ToListAsync(ct).ConfigureAwait(false);
        var policies = await db.Policies.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
        var defaultName = policies.FirstOrDefault(p => p.IsDefault)?.Name ?? "Default";
        var rows = computers.OrderBy(c => c.Hostname, StringComparer.OrdinalIgnoreCase).Select(c =>
        {
            var failed = c.ControlStatusJson is null
                ? []
                : (JsonSerializer.Deserialize<List<ControlStatus>>(c.ControlStatusJson, Json) ?? []).Where(s => s.State == ControlState.Failed).Select(s => s.Control.ToString());
            return Row(c.Hostname, c.Status == ComputerStatus.Trusted ? "Approved" : "Waiting for approval",
                ComputerPresence.IsOnline(c.LastSeenAtUtc, c.HeartbeatIntervalSeconds, now) ? "yes" : "no",
                c.LastSeenAtUtc is { } seen ? Local(seen) : null, c.OsName, c.AgentVersion,
                c.PolicyId is { } pid ? policies.FirstOrDefault(p => p.Id == pid)?.Name : defaultName,
                string.Create(CultureInfo.InvariantCulture, $"{c.AppliedPolicyVersion}/{c.PolicyVersion}"),
                string.Join(", ", failed));
        }).ToList();
        return new ReportSection("Computers and protection status now",
            ["Computer", "Status", "Online", "Last contact", "Windows", "Agent", "Policy", "Policy version (applied/latest)", "Protections not working"], rows);
    }

    private async Task<List<ReportSection>> AuditAsync(DateTimeOffset from, DateTimeOffset to, List<KeyValuePair<string, string>> facts, CancellationToken ct)
    {
        var check = await audit.VerifyAsync(ct).ConfigureAwait(false);
        facts.Add(new("Integrity check now", (check.IsIntact ? "OK — " : "PROBLEM — ") + check.Message));
        var rows = await db.AuditEntries.AsNoTracking().Where(e => e.OccurredAtUtc >= from && e.OccurredAtUtc < to)
            .OrderBy(e => e.Id).ToListAsync(ct).ConfigureAwait(false);
        return
        [
            Limit(new ReportSection("Audit log", ["#", "Time", "Who", "Action", "Result", "Target", "Details", "From address"],
                rows.Select(e => Row(e.Id.ToString(CultureInfo.InvariantCulture), Local(e.OccurredAtUtc), e.ActorName ?? e.ActorType.ToString(), e.Action,
                    e.Outcome.ToString(), e.TargetType is null ? null : $"{e.TargetType} {e.TargetId}", e.Details, e.SourceIp)).ToList())),
        ];
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>"Protection problem" events are not blocked activity; ransomware blocks are.</summary>
    private static bool BlockedFilter(SecurityEvent e) => e.EventType != nameof(SecurityEventType.PolicyViolation) || IsRansomware(e);

    private static bool IsRansomware(SecurityEvent e) =>
        e.EventType == nameof(SecurityEventType.PolicyViolation) && e.Details?.StartsWith("Ransomware protection", StringComparison.Ordinal) == true;

    /// <summary>Plain-language names for event types.</summary>
    public static string EventName(string type, SecurityEvent? e = null) => type switch
    {
        nameof(SecurityEventType.RemovableStorageBlocked) => "USB storage blocked",
        nameof(SecurityEventType.UnauthorizedUsbConnection) => "Blocked device connected",
        nameof(SecurityEventType.FileTransferBlocked) => "File transfer blocked",
        nameof(SecurityEventType.UnauthorizedApplicationBlocked) => e?.Severity == EventSeverities.Information ? "Program (audit: would be blocked)" : "Program blocked",
        nameof(SecurityEventType.PolicyViolation) => e is not null && IsRansomware(e) ? "Ransomware protection" : "Protection problem",
        nameof(SecurityEventType.PolicyTamperAttempt) => "Tampering",
        nameof(SecurityEventType.UnauthorizedSoftwareInstallAttempt) => "Installation blocked",
        nameof(SecurityEventType.AgentStoppedOrUnavailable) => "Agent stopped",
        nameof(SecurityEventType.FailedLogin) => "Failed Windows sign-in",
        nameof(SecurityEventType.SuccessfulLogin) => "Windows sign-in",
        nameof(SecurityEventType.Logout) => "Windows sign-out",
        nameof(SecurityEventType.ApprovedDeviceConnected) => "Approved USB drive connected",
        nameof(SecurityEventType.DeviceConnected) => "Device connected",
        nameof(SecurityEventType.DeviceDisconnected) => "Device disconnected",
        nameof(SecurityEventType.ProtectedFileAccess) => "Company file used",
        nameof(SecurityEventType.SoftwareInstalled) => "Program installed",
        nameof(SecurityEventType.SoftwareRemoved) => "Program removed",
        nameof(SecurityEventType.SoftwareDeployment) => "Approved installation",
        nameof(SecurityEventType.PolicyApplied) => "Policy applied",
        nameof(SecurityEventType.AgentStarted) => "Agent started",
        _ => type,
    };

    private string Local(DateTimeOffset time, string format = "yyyy-MM-dd HH:mm") =>
        TimeZoneInfo.ConvertTime(time, clock.LocalTimeZone).ToString(format, CultureInfo.InvariantCulture);

    private static string N(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static List<string> Row(params string?[] cells) => cells.Select(c => c ?? string.Empty).ToList();

    private static ReportSection Limit(ReportSection section) => section.Rows.Count <= MaxRowsPerSection
        ? section
        : section with
        {
            Rows = section.Rows.Take(MaxRowsPerSection).ToList(),
            Note = string.Create(CultureInfo.InvariantCulture, $"Only the first {MaxRowsPerSection} of {section.Rows.Count} rows are included. Choose a shorter period or one computer."),
        };
}
