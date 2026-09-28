using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Security events reported by computers (device connections, policy changes, agent start-ups...).</summary>
public sealed partial class EventsViewModel(ShellViewModel shell) : SectionViewModel("Security Events")
{
    private const int PageSize = 50;

    public ObservableCollection<SecurityEventResponse> Items { get; } = [];

    [ObservableProperty]
    public partial string Search { get; set; } = string.Empty;

    public IReadOnlyList<NamedChoice<string?>> SeverityFilters { get; } =
        [new(null, "All severities"), new(EventSeverities.Critical, "Critical"), new(EventSeverities.Warning, "Warning"), new(EventSeverities.Information, "Information")];

    [ObservableProperty]
    public partial NamedChoice<string?>? SeverityFilter { get; set; }

    public IReadOnlyList<NamedChoice<string?>> TypeFilters { get; } =
        [new NamedChoice<string?>(null, "All events"), .. Enum.GetValues<SecurityEventType>().Select(t => new NamedChoice<string?>(t.ToString(), t.ToString())).OrderBy(c => c.Label, StringComparer.Ordinal)];

    [ObservableProperty]
    public partial NamedChoice<string?>? TypeFilter { get; set; }

    /// <summary>Optional: only events on or after this day.</summary>
    [ObservableProperty]
    public partial DateTime? FromDate { get; set; }

    /// <summary>Optional: only events up to and including this day.</summary>
    [ObservableProperty]
    public partial DateTime? ToDate { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int Page { get; set; } = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int TotalCount { get; set; }

    public int TotalPages => Math.Max(1, (TotalCount + PageSize - 1) / PageSize);

    public string PageText => $"Page {Page} of {TotalPages} · {TotalCount} events";

    public override Task ActivateAsync()
    {
        SeverityFilter ??= SeverityFilters[0];
        TypeFilter ??= TypeFilters[0];
        return LoadAsync();
    }

    [RelayCommand]
    private Task LoadAsync() => RunAsync(async () =>
    {
        var result = await shell.Api.ListEventsAsync(Page, PageSize, null, Search, SeverityFilter?.Value, TypeFilter?.Value, Start(), End());
        Items.Clear();
        foreach (var item in result.Items)
        {
            Items.Add(item);
        }

        TotalCount = result.TotalCount;
        OnPropertyChanged(nameof(TotalPages));
    });

    [RelayCommand]
    private Task ApplyFilterAsync()
    {
        Page = 1;
        return LoadAsync();
    }

    [RelayCommand]
    private Task ClearFiltersAsync()
    {
        Search = string.Empty;
        SeverityFilter = SeverityFilters[0];
        TypeFilter = TypeFilters[0];
        FromDate = ToDate = null;
        return ApplyFilterAsync();
    }

    [RelayCommand]
    private Task UsbLogAsync()
    {
        Search = string.Empty;
        TypeFilter = TypeFilters.First(t => t.Value == nameof(SecurityEventType.DeviceConnected));
        return ApplyFilterAsync();
    }

    /// <summary>Saves the events of the chosen days (default: the last 30 days) as a CSV file for Excel.</summary>
    [RelayCommand]
    private Task ExportAsync() => RunAsync(async () =>
    {
        var from = Start() ?? new DateTimeOffset(DateTime.Today.AddDays(-29));
        var to = End() ?? new DateTimeOffset(DateTime.Today.AddDays(1));
        var path = shell.Ui.PickSaveFile("Save events", "CSV file for Excel (*.csv)|*.csv", $"events-{from.LocalDateTime:yyyy-MM-dd}-to-{to.LocalDateTime.AddDays(-1):yyyy-MM-dd}.csv");
        if (path is null)
        {
            return;
        }

        await File.WriteAllBytesAsync(path, await shell.Api.DownloadReportAsync("events", from, to, null, ReportFormats.Csv));
        InfoMessage = $"Saved: {path} (all events of those days; for other reports see 'Reports').";
        shell.Ui.OpenFile(path);
    });

    [RelayCommand]
    private Task PreviousPageAsync()
    {
        if (Page <= 1)
        {
            return Task.CompletedTask;
        }

        Page--;
        return LoadAsync();
    }

    [RelayCommand]
    private Task NextPageAsync()
    {
        if (Page >= TotalPages)
        {
            return Task.CompletedTask;
        }

        Page++;
        return LoadAsync();
    }

    private DateTimeOffset? Start() => FromDate is { } d ? new DateTimeOffset(DateTime.SpecifyKind(d.Date, DateTimeKind.Local)) : null;

    private DateTimeOffset? End() => ToDate is { } d ? new DateTimeOffset(DateTime.SpecifyKind(d.Date.AddDays(1), DateTimeKind.Local)) : null;
}
