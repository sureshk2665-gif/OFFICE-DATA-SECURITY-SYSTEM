using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Reports;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class ReportTests
{
    private static string Range(ServerFactory server) =>
        $"from={Uri.EscapeDataString(server.Clock.GetUtcNow().AddDays(-1).ToString("O"))}&to={Uri.EscapeDataString(server.Clock.GetUtcNow().AddMinutes(1).ToString("O"))}";

    private static List<string[]> ParseCsv(byte[] content)
    {
        var text = Encoding.UTF8.GetString(content);
        Assert.StartsWith("\uFEFF", text, StringComparison.Ordinal); // BOM so Excel reads UTF-8
        var rows = new List<string[]>();
        var row = new List<string>();
        var cell = new StringBuilder();
        var quoted = false;
        for (var i = 1; i < text.Length; i++)
        {
            var ch = text[i];
            if (quoted)
            {
                if (ch == '"' && i + 1 < text.Length && text[i + 1] == '"')
                {
                    cell.Append('"');
                    i++;
                }
                else if (ch == '"')
                {
                    quoted = false;
                }
                else
                {
                    cell.Append(ch);
                }
            }
            else if (ch == '"')
            {
                quoted = true;
            }
            else if (ch == ',')
            {
                row.Add(cell.ToString());
                cell.Clear();
            }
            else if (ch == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
            {
                row.Add(cell.ToString());
                cell.Clear();
                rows.Add([.. row]);
                row.Clear();
                i++;
            }
            else
            {
                cell.Append(ch);
            }
        }

        return rows;
    }

    [Fact]
    public async Task Reports_reconcile_with_the_stored_events_and_every_export_is_audited_with_its_hash()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        using var computer = AlertTests.AgentClient(server, agent);

        await AlertTests.SendAsync(computer, server,
            (SecurityEventType.RemovableStorageBlocked, EventSeverities.Warning, "USB drive blocked: Kingston"),
            (SecurityEventType.RemovableStorageBlocked, EventSeverities.Warning, "=HYPERLINK(\"http://evil\")"),
            (SecurityEventType.UnauthorizedApplicationBlocked, EventSeverities.Warning, "Blocked by Application Control: C:\\Users\\a\\game.exe"),
            (SecurityEventType.PolicyViolation, EventSeverities.Warning, "Ransomware protection blocked evil.exe from changing D:\\Company\\a.xlsx (user PC\\anna)."),
            (SecurityEventType.PolicyViolation, EventSeverities.Warning, "BitLocker could not be enforced: ..."), // not blocked activity
            (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "restored"),
            (SecurityEventType.FailedLogin, EventSeverities.Warning, "Failed Windows sign-in for PC\\anna (at the computer): wrong password."),
            (SecurityEventType.ProtectedFileAccess, EventSeverities.Information, "PC\\anna opened D:\\Company\\salaries.xlsx (program: excel.exe)."));

        // Blocked activity: exactly the 5 blocking events.
        var response = await admin.GetAsync(new Uri($"{ApiRoutes.Report("blocked")}?{Range(server)}&format=csv", UriKind.Relative));
        response.EnsureSuccessStatusCode();
        Assert.Equal("text/csv", response.Content.Headers.ContentType!.MediaType);
        var csv = await response.Content.ReadAsByteArrayAsync();
        var rows = ParseCsv(csv);
        Assert.Equal(["Time", "Computer", "Event", "Severity", "Details"], rows[0]);
        Assert.Equal(5, rows.Count - 1);
        Assert.Contains(rows, r => r[2] == "Ransomware protection");
        Assert.DoesNotContain(rows, r => r[4].StartsWith("BitLocker", StringComparison.Ordinal));
        // A cell a spreadsheet would run as a formula is neutralised.
        Assert.Contains(rows, r => r[4] == "'=HYPERLINK(\"http://evil\")");

        // Security summary: the per-type totals equal the stored events.
        var summary = ParseCsv(await (await admin.GetAsync(new Uri($"{ApiRoutes.Report("security-summary")}?{Range(server)}&format=csv", UriKind.Relative)))
            .EnsureSuccessStatusCode().Content.ReadAsByteArrayAsync());
        var byTypeStart = summary.FindIndex(r => r[0] == "Security events by type");
        var byType = summary.Skip(byTypeStart + 2).TakeWhile(r => r.Length > 1).ToList();
        var stored = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?pageSize=200");
        Assert.Equal(stored!.TotalCount, byType.Sum(r => int.Parse(r[4], System.Globalization.CultureInfo.InvariantCulture)));
        Assert.Equal("2", byType.Single(r => r[0] == "USB storage blocked")[2]); // two warnings
        var perComputer = summary.Skip(summary.FindIndex(r => r[0] == "Computers with blocked activity") + 2).First();
        // Columns: computer, blocked USB/phone, blocked programs, ransomware blocks, tampering, failed Windows sign-ins, total.
        Assert.Equal(["2", "1", "1", "1", "1", "6"], perComputer[1..]);

        // PDF: a real PDF document.
        response = await admin.GetAsync(new Uri($"{ApiRoutes.Report("security-summary")}?{Range(server)}&format=pdf", UriKind.Relative));
        response.EnsureSuccessStatusCode();
        Assert.Equal("application/pdf", response.Content.Headers.ContentType!.MediaType);
        var pdf = await response.Content.ReadAsByteArrayAsync();
        Assert.StartsWith("%PDF-1.4", Encoding.Latin1.GetString(pdf, 0, 8), StringComparison.Ordinal);
        Assert.EndsWith("%%EOF\n", Encoding.Latin1.GetString(pdf), StringComparison.Ordinal);
        Assert.Contains("Security summary", Encoding.Latin1.GetString(pdf), StringComparison.Ordinal);

        // Every export is in the audit log, with the SHA-256 of exactly what was downloaded.
        var auditLog = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        var exports = auditLog!.Items.Where(e => e.Action == "report.export").ToList();
        Assert.Equal(3, exports.Count);
        Assert.Contains(exports, e => e.Details!.Contains(Convert.ToHexString(SHA256.HashData(pdf)).ToLowerInvariant(), StringComparison.Ordinal));
        Assert.Contains(exports, e => e.Details!.Contains(Convert.ToHexString(SHA256.HashData(csv)).ToLowerInvariant(), StringComparison.Ordinal) && e.Details.Contains("5 rows", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Every_report_type_builds_in_both_formats_for_administrators_and_auditors_but_not_staff()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor7", AdminRoles.Auditor);
        using var auditor = server.Client(auditorToken);

        var types = await auditor.GetFromJsonAsync<List<ReportTypeInfo>>(ApiRoutes.Reports);
        Assert.True(types!.Count >= 10);
        foreach (var type in types)
        {
            foreach (var format in new[] { "csv", "pdf" })
            {
                var computerPart = type.UsesComputer ? $"&computerId={agent.ComputerId}" : string.Empty;
                var response = await auditor.GetAsync(new Uri($"{ApiRoutes.Report(type.Code)}?{Range(server)}&format={format}{computerPart}", UriKind.Relative));
                Assert.True(response.IsSuccessStatusCode, $"{type.Code} {format}: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
                Assert.True((await response.Content.ReadAsByteArrayAsync()).Length > 10);
            }
        }

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync(new Uri($"{ApiRoutes.Report("nope")}?format=csv", UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync(new Uri($"{ApiRoutes.Report("events")}?format=docx", UriKind.Relative))).StatusCode);
        var backwards = $"from={Uri.EscapeDataString(server.Clock.GetUtcNow().ToString("O"))}&to={Uri.EscapeDataString(server.Clock.GetUtcNow().AddDays(-1).ToString("O"))}";
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync(new Uri($"{ApiRoutes.Report("events")}?{backwards}", UriKind.Relative))).StatusCode);

        var (_, staffToken) = await server.CreateActiveStaffAsync(owner, "EMP-R1", "Staff member pass 2026");
        using var staff = server.Client(staffToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri($"{ApiRoutes.Report("events")}?format=csv", UriKind.Relative))).StatusCode);
    }

    [Fact]
    public async Task Weekly_and_monthly_summaries_are_saved_once_and_can_be_downloaded()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);

        await using (var scope = server.Services.CreateAsyncScope())
        {
            var scheduled = scope.ServiceProvider.GetRequiredService<ScheduledReports>();
            var first = await scheduled.RunOnceAsync();
            Assert.Equal(2, first.Count);
            Assert.Contains(first, f => f.StartsWith(ScheduledReports.WeeklyPrefix, StringComparison.Ordinal));
            Assert.Contains(first, f => f.StartsWith(ScheduledReports.MonthlyPrefix, StringComparison.Ordinal));
            Assert.Empty(await scheduled.RunOnceAsync()); // already saved
        }

        var saved = await admin.GetFromJsonAsync<List<SavedReportInfo>>(ApiRoutes.SavedReports);
        Assert.Equal(2, saved!.Count);
        var weekly = saved.Single(s => s.FileName.StartsWith(ScheduledReports.WeeklyPrefix, StringComparison.Ordinal));
        var content = await (await admin.GetAsync(new Uri(ApiRoutes.SavedReport(weekly.FileName), UriKind.Relative))).EnsureSuccessStatusCode().Content.ReadAsByteArrayAsync();
        Assert.StartsWith("%PDF", Encoding.Latin1.GetString(content, 0, 4), StringComparison.Ordinal);
        Assert.Contains("Weekly security summary", Encoding.Latin1.GetString(content), StringComparison.Ordinal);

        // Only listed file names can be downloaded.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync(new Uri(ApiRoutes.SavedReport("..\\office-security.db"), UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync(new Uri(ApiRoutes.SavedReport("office-security.db"), UriKind.Relative))).StatusCode);

        // A week later there is one more weekly summary.
        server.Clock.Advance(TimeSpan.FromDays(7));
        await using (var scope = server.Services.CreateAsyncScope())
        {
            var next = await scope.ServiceProvider.GetRequiredService<ScheduledReports>().RunOnceAsync();
            Assert.Contains(next, f => f.StartsWith(ScheduledReports.WeeklyPrefix, StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Events_can_be_filtered_by_severity_type_and_time()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        using var computer = AlertTests.AgentClient(server, agent);
        var start = server.Clock.GetUtcNow();
        await AlertTests.SendAsync(computer, server,
            (SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "a"),
            (SecurityEventType.RemovableStorageBlocked, EventSeverities.Warning, "b"));

        var critical = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?severity=Critical");
        Assert.All(critical!.Items, e => Assert.Equal(EventSeverities.Critical, e.Severity));
        Assert.Contains(critical.Items, e => e.Details == "a");

        var usb = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?type=RemovableStorageBlocked");
        Assert.Equal("b", Assert.Single(usb!.Items).Details);

        var later = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?from={Uri.EscapeDataString(start.AddMinutes(1).ToString("O"))}");
        Assert.Empty(later!.Items);
    }
}
