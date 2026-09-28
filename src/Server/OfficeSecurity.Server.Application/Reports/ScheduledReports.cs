using System.Globalization;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Application.Reports;

/// <summary>Where the automatic summaries are saved (the server's data folder, "reports").</summary>
public sealed record SavedReportsOptions(string Directory);

/// <summary>
/// Saves a security summary (PDF) for every completed week (Monday to Monday) and every completed month, in the
/// server's time zone. A missing summary is created at the next run, so a server that was switched off catches up
/// on the most recent week and month.
/// </summary>
public sealed class ScheduledReports(ReportService reports, AuditLog audit, SavedReportsOptions options, TimeProvider clock)
{
    public const string WeeklyPrefix = "weekly-security-summary-";
    public const string MonthlyPrefix = "monthly-security-summary-";

    public async Task<IReadOnlyList<string>> RunOnceAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(options.Directory);
        var zone = clock.LocalTimeZone;
        var today = TimeZoneInfo.ConvertTime(clock.GetUtcNow(), zone).Date;
        var weekStart = today.AddDays(-(((int)today.DayOfWeek + 6) % 7)); // this week's Monday
        var monthStart = new DateTime(today.Year, today.Month, 1, 0, 0, 0, DateTimeKind.Unspecified);

        var saved = new List<string>();
        await SaveAsync(WeeklyPrefix, weekStart.AddDays(-7), weekStart, "weekly", saved, ct).ConfigureAwait(false);
        await SaveAsync(MonthlyPrefix, monthStart.AddMonths(-1), monthStart, "monthly", saved, ct).ConfigureAwait(false);
        return saved;
    }

    private async Task SaveAsync(string prefix, DateTime localFrom, DateTime localTo, string kind, List<string> saved, CancellationToken ct)
    {
        var name = string.Create(CultureInfo.InvariantCulture, $"{prefix}{localFrom:yyyy-MM-dd}-to-{localTo.AddDays(-1):yyyy-MM-dd}.pdf");
        var path = Path.Combine(options.Directory, name);
        if (File.Exists(path))
        {
            return;
        }

        var zone = clock.LocalTimeZone;
        var from = new DateTimeOffset(localFrom, zone.GetUtcOffset(localFrom));
        var to = new DateTimeOffset(localTo, zone.GetUtcOffset(localTo));
        var document = await reports.BuildAsync(ReportService.SecuritySummary, from, to, null, $"the server (automatic {kind} summary)", ct).ConfigureAwait(false);
        var file = reports.Render(document with { Title = $"{(kind == "weekly" ? "Weekly" : "Monthly")} security summary" }, ReportService.SecuritySummary, from, to, "pdf");
        var temp = path + ".tmp";
        await File.WriteAllBytesAsync(temp, file.Content, ct).ConfigureAwait(false);
        File.Move(temp, path, overwrite: true);
        await audit.RecordAndSaveAsync(RequestContext.System, new AuditRecord("report.scheduled", TargetType: "Report", TargetId: name,
            Details: string.Create(CultureInfo.InvariantCulture, $"Automatic {kind} security summary saved ({file.Content.Length} bytes)")), ct).ConfigureAwait(false);
        saved.Add(name);
    }

    /// <summary>The saved summaries, newest first.</summary>
    public IReadOnlyList<Contracts.SavedReportInfo> List()
    {
        if (!Directory.Exists(options.Directory))
        {
            return [];
        }

        return new DirectoryInfo(options.Directory).GetFiles("*.pdf")
            .Where(f => f.Name.StartsWith(WeeklyPrefix, StringComparison.Ordinal) || f.Name.StartsWith(MonthlyPrefix, StringComparison.Ordinal))
            .OrderByDescending(f => f.Name.StartsWith(WeeklyPrefix, StringComparison.Ordinal) ? f.Name[WeeklyPrefix.Length..] : f.Name[MonthlyPrefix.Length..], StringComparer.Ordinal)
            .ThenBy(f => f.Name, StringComparer.Ordinal)
            .Select(f => new Contracts.SavedReportInfo(f.Name, f.Name.StartsWith(WeeklyPrefix, StringComparison.Ordinal) ? "Weekly security summary" : "Monthly security summary",
                new DateTimeOffset(f.CreationTimeUtc, TimeSpan.Zero), f.Length))
            .ToList();
    }

    /// <summary>A saved summary's content, or null. Only names from <see cref="List"/> are accepted (no paths).</summary>
    public byte[]? Read(string fileName)
    {
        var match = List().FirstOrDefault(r => string.Equals(r.FileName, fileName, StringComparison.Ordinal));
        return match is null ? null : File.ReadAllBytes(Path.Combine(options.Directory, match.FileName));
    }
}
