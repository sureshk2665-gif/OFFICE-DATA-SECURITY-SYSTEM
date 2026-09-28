using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Reports: choose a report, a period and a computer; save it as PDF or CSV (Excel).</summary>
public sealed partial class ReportsViewModel(ShellViewModel shell) : SectionViewModel("Reports")
{
    public const string Custom = "custom";

    public ObservableCollection<ReportTypeInfo> Types { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UsesPeriod), nameof(UsesComputer))]
    public partial ReportTypeInfo? SelectedType { get; set; }

    public bool UsesPeriod => SelectedType?.UsesPeriod ?? true;

    public bool UsesComputer => SelectedType?.UsesComputer ?? false;

    public IReadOnlyList<NamedChoice<string>> Periods { get; } =
    [
        new("7", "Last 7 days"), new("30", "Last 30 days"), new("this-month", "This month"), new("last-month", "Last month"),
        new("365", "Last 12 months"), new(Custom, "Choose dates…"),
    ];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCustomPeriod))]
    public partial NamedChoice<string>? Period { get; set; }

    public bool IsCustomPeriod => Period?.Value == Custom;

    [ObservableProperty]
    public partial DateTime? FromDate { get; set; } = DateTime.Today.AddDays(-7);

    [ObservableProperty]
    public partial DateTime? ToDate { get; set; } = DateTime.Today;

    public ObservableCollection<NamedChoice<Guid?>> Computers { get; } = [];

    [ObservableProperty]
    public partial NamedChoice<Guid?>? Computer { get; set; }

    public IReadOnlyList<NamedChoice<string>> Formats { get; } =
        [new(ReportFormats.Pdf, "PDF (to read or print)"), new(ReportFormats.Csv, "CSV (to open in Excel)")];

    [ObservableProperty]
    public partial NamedChoice<string>? Format { get; set; }

    public ObservableCollection<SavedReportInfo> SavedReports { get; } = [];

    [ObservableProperty]
    public partial SavedReportInfo? SelectedSaved { get; set; }

    public override Task ActivateAsync()
    {
        Period ??= Periods[0];
        Format ??= Formats[0];
        return RunAsync(LoadAsync);
    }

    /// <summary>Used by the start-up self-test to render the page without a server.</summary>
    internal void ShowSampleForSelfTest()
    {
        Types.Add(new ReportTypeInfo("security-summary", "Security summary", "Totals for the period.", true, false));
        Types.Add(new ReportTypeInfo("blocked", "Blocked activity", "Every blocked USB drive…", true, true));
        SelectedType = Types[1];
        Period = Periods[^1];
        Format = Formats[0];
        Computers.Add(new NamedChoice<Guid?>(null, "All computers"));
        Computer = Computers[0];
        SavedReports.Add(new SavedReportInfo("weekly-security-summary-2026-09-21-to-2026-09-27.pdf", "Weekly security summary", DateTimeOffset.UtcNow, 12345));
    }

    /// <summary>The chosen period as UTC times (whole days in this computer's time zone; the end day is included).</summary>
    public (DateTimeOffset From, DateTimeOffset To) Range(DateTime today)
    {
        var end = today.AddDays(1);
        var start = Period?.Value switch
        {
            "30" => end.AddDays(-30),
            "365" => end.AddDays(-365),
            "this-month" => new DateTime(today.Year, today.Month, 1, 0, 0, 0, DateTimeKind.Local),
            "last-month" => new DateTime(today.Year, today.Month, 1, 0, 0, 0, DateTimeKind.Local).AddMonths(-1),
            Custom => (FromDate ?? today).Date,
            _ => end.AddDays(-7),
        };
        if (Period?.Value == "last-month")
        {
            end = new DateTime(today.Year, today.Month, 1, 0, 0, 0, DateTimeKind.Local);
        }
        else if (Period?.Value == Custom)
        {
            end = (ToDate ?? today).Date.AddDays(1);
        }

        return (new DateTimeOffset(DateTime.SpecifyKind(start, DateTimeKind.Local)), new DateTimeOffset(DateTime.SpecifyKind(end, DateTimeKind.Local)));
    }

    [RelayCommand]
    private Task CreateAsync() => RunAsync(async () =>
    {
        InfoMessage = string.Empty;
        if (SelectedType is not { } type || Format is not { } format)
        {
            ErrorMessage = "Choose a report.";
            return;
        }

        var (from, to) = Range(DateTime.Today);
        if (from >= to)
        {
            ErrorMessage = "The start date must be before the end date.";
            return;
        }

        var extension = format.Value;
        var suggested = $"{type.Code}-{from.LocalDateTime:yyyy-MM-dd}-to-{to.LocalDateTime.AddDays(-1):yyyy-MM-dd}.{extension}";
        var path = shell.Ui.PickSaveFile("Save report", extension == ReportFormats.Pdf ? "PDF document (*.pdf)|*.pdf" : "CSV file for Excel (*.csv)|*.csv", suggested);
        if (path is null)
        {
            return;
        }

        var content = await shell.Api.DownloadReportAsync(type.Code, from, to, UsesComputer ? Computer?.Value : null, extension);
        await File.WriteAllBytesAsync(path, content);
        InfoMessage = $"Saved: {path}. The export is recorded in the audit log.";
        shell.Ui.OpenFile(path);
    });

    [RelayCommand]
    private Task DownloadSavedAsync() => RunAsync(async () =>
    {
        if (SelectedSaved is not { } saved)
        {
            ErrorMessage = "Select a saved summary first.";
            return;
        }

        var path = shell.Ui.PickSaveFile("Save summary", "PDF document (*.pdf)|*.pdf", saved.FileName);
        if (path is null)
        {
            return;
        }

        await File.WriteAllBytesAsync(path, await shell.Api.DownloadSavedReportAsync(saved.FileName));
        InfoMessage = $"Saved: {path}";
        shell.Ui.OpenFile(path);
    });

    private async Task LoadAsync()
    {
        var selected = SelectedType?.Code;
        var types = await shell.Api.ListReportTypesAsync();
        Types.Clear();
        foreach (var t in types)
        {
            Types.Add(t);
        }

        SelectedType = Types.FirstOrDefault(t => t.Code == selected) ?? Types.FirstOrDefault();

        var computers = await shell.Api.ListComputersAsync(1, 200, null, ComputerStatuses.Trusted);
        var chosen = Computer?.Value;
        Computers.Clear();
        Computers.Add(new NamedChoice<Guid?>(null, "All computers"));
        foreach (var c in computers.Items.OrderBy(c => c.Hostname, StringComparer.OrdinalIgnoreCase))
        {
            Computers.Add(new NamedChoice<Guid?>(c.Id, c.Hostname));
        }

        Computer = Computers.FirstOrDefault(c => c.Value == chosen) ?? Computers[0];

        SavedReports.Clear();
        foreach (var s in await shell.Api.ListSavedReportsAsync())
        {
            SavedReports.Add(s);
        }
    }
}
