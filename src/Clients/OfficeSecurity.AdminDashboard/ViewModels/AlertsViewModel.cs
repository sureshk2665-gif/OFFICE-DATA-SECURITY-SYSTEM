using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>An alert rule as edited on the page.</summary>
public sealed partial class AlertRuleRow(AlertRuleResponse rule) : ObservableObject
{
    public string Code { get; } = rule.Code;

    public string Name { get; } = rule.Name;

    public string Description { get; } = rule.Description;

    public string? ThresholdMeaning { get; } = rule.ThresholdMeaning;

    public bool HasThreshold => ThresholdMeaning is not null;

    public bool UsesWindow { get; } = rule.UsesWindow;

    public string LastChange { get; } = rule.UpdatedBy is null ? "default settings" : $"changed by {rule.UpdatedBy}";

    public IReadOnlyList<string> Severities { get; } = [EventSeverities.Critical, EventSeverities.Warning, EventSeverities.Information];

    [ObservableProperty]
    public partial bool Enabled { get; set; } = rule.Enabled;

    [ObservableProperty]
    public partial string Severity { get; set; } = rule.Severity;

    [ObservableProperty]
    public partial string Threshold { get; set; } = rule.Threshold.ToString(System.Globalization.CultureInfo.CurrentCulture);

    [ObservableProperty]
    public partial string WindowMinutes { get; set; } = rule.WindowMinutes.ToString(System.Globalization.CultureInfo.CurrentCulture);
}

/// <summary>Security alerts: what needs attention, acknowledge and resolve, and the alert rules.</summary>
public sealed partial class AlertsViewModel(ShellViewModel shell, bool canWrite) : SectionViewModel("Security Alerts")
{
    private const int PageSize = 50;

    public bool CanWrite { get; } = canWrite;

    public ObservableCollection<AlertResponse> Items { get; } = [];

    public IReadOnlyList<NamedChoice<string>> StatusFilters { get; } =
    [
        new(AlertStatuses.Active, "Not resolved"), new(AlertStatuses.Open, "New (not acknowledged)"), new(AlertStatuses.Acknowledged, "Acknowledged"),
        new(AlertStatuses.Resolved, "Resolved"), new("All", "All"),
    ];

    public IReadOnlyList<NamedChoice<string?>> SeverityFilters { get; } =
        [new(null, "All severities"), new(EventSeverities.Critical, "Critical"), new(EventSeverities.Warning, "Warning"), new(EventSeverities.Information, "Information")];

    [ObservableProperty]
    public partial NamedChoice<string> StatusFilter { get; set; } = null!;

    [ObservableProperty]
    public partial NamedChoice<string?> SeverityFilter { get; set; } = null!;

    [ObservableProperty]
    public partial string Search { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int Page { get; set; } = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int TotalCount { get; set; }

    public int TotalPages => Math.Max(1, (TotalCount + PageSize - 1) / PageSize);

    public string PageText => $"Page {Page} of {TotalPages} · {TotalCount} alerts";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(CanAcknowledge), nameof(CanResolve), nameof(SelectedText))]
    public partial AlertResponse? Selected { get; set; }

    public bool HasSelection => Selected is not null;

    public bool CanAcknowledge => CanWrite && Selected?.Status == AlertStatuses.Open;

    public bool CanResolve => CanWrite && Selected is { Status: not AlertStatuses.Resolved };

    public string SelectedText => Selected is not { } a
        ? string.Empty
        : string.Join(Environment.NewLine, new[]
        {
            $"{a.Severity} · {a.RuleName}{(a.ComputerName is null ? string.Empty : " · " + a.ComputerName)}",
            $"First seen {a.FirstSeenUtc.ToLocalTime():dd MMM yyyy HH:mm} · last seen {a.LastSeenUtc.ToLocalTime():dd MMM yyyy HH:mm} · {a.EventCount} time(s)",
            a.Details ?? string.Empty,
            a.AcknowledgedBy is null ? string.Empty : $"Acknowledged by {a.AcknowledgedBy} at {a.AcknowledgedAtUtc?.ToLocalTime():dd MMM HH:mm}",
            a.ResolvedBy is null ? string.Empty : $"Resolved by {a.ResolvedBy} at {a.ResolvedAtUtc?.ToLocalTime():dd MMM HH:mm}{(a.ResolutionNote is null ? string.Empty : ": " + a.ResolutionNote)}",
        }.Where(l => l.Length > 0));

    [ObservableProperty]
    public partial string ResolveNote { get; set; } = string.Empty;

    // ---- badge in the sidebar
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(NavTitle))]
    public partial AlertSummaryResponse? Summary { get; set; }

    public override string NavTitle => Summary is { Open: > 0 } s
        ? $"Security Alerts ({s.Open}{(s.OpenCritical > 0 ? $", {s.OpenCritical} critical" : string.Empty)})"
        : Title;

    // ---- rules
    public ObservableCollection<AlertRuleRow> Rules { get; } = [];

    [ObservableProperty]
    public partial AlertRuleRow? SelectedRule { get; set; }

    public override Task ActivateAsync()
    {
        StatusFilter ??= StatusFilters[0];
        SeverityFilter ??= SeverityFilters[0];
        return LoadAsync();
    }

    /// <summary>Used by the start-up self-test to render the page without a server.</summary>
    internal void ShowSampleForSelfTest()
    {
        StatusFilter = StatusFilters[0];
        SeverityFilter = SeverityFilters[0];
        var now = DateTimeOffset.UtcNow;
        Items.Add(new AlertResponse(Guid.NewGuid(), "tamper", "Protection tampered with", EventSeverities.Critical, Guid.NewGuid(), "PC-01",
            "Protection tampered with on PC-01", "USB drive blocking: settings changed and restored.", 2, now, now, AlertStatuses.Open, null, null, null, null, null));
        Selected = Items[0];
        Rules.Add(new AlertRuleRow(new AlertRuleResponse("windows-failed-sign-ins", "Repeated failed Windows sign-ins", "Many wrong passwords.", true,
            EventSeverities.Warning, 5, 15, "failed sign-ins", true, null, null)));
        Summary = new AlertSummaryResponse(1, 1, 0, now);
    }

    /// <summary>Refreshes the sidebar count (called regularly by the workspace).</summary>
    public async Task RefreshSummaryAsync()
    {
        try
        {
            Summary = await shell.Api.GetAlertSummaryAsync();
        }
        catch (ApiException)
        {
            // The badge is only a hint; errors show when the page is opened.
        }
    }

    [RelayCommand]
    private Task LoadAsync() => RunAsync(FetchAsync);

    private async Task FetchAsync()
    {
        var selectedId = Selected?.Id;
        var result = await shell.Api.ListAlertsAsync(Page, PageSize, StatusFilter?.Value, SeverityFilter?.Value, Search);
        Items.Clear();
        foreach (var item in result.Items)
        {
            Items.Add(item);
        }

        TotalCount = result.TotalCount;
        OnPropertyChanged(nameof(TotalPages));
        Selected = Items.FirstOrDefault(i => i.Id == selectedId);
        Summary = await shell.Api.GetAlertSummaryAsync();

        var rules = await shell.Api.ListAlertRulesAsync();
        var selectedRule = SelectedRule?.Code;
        Rules.Clear();
        foreach (var rule in rules)
        {
            Rules.Add(new AlertRuleRow(rule));
        }

        SelectedRule = Rules.FirstOrDefault(r => r.Code == selectedRule);
    }

    [RelayCommand]
    private Task ApplyFilterAsync()
    {
        Page = 1;
        return LoadAsync();
    }

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

    [RelayCommand]
    private Task AcknowledgeAsync() => RunAsync(async () =>
    {
        if (Selected is { } alert && CanAcknowledge)
        {
            await shell.Api.AcknowledgeAlertAsync(alert.Id);
            InfoMessage = "Acknowledged: other administrators can see that you are looking at it.";
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task ResolveAsync() => RunAsync(async () =>
    {
        if (Selected is { } alert && CanResolve && shell.Ui.Confirm("Resolve alert", $"Mark \"{alert.Title}\" as resolved?"))
        {
            await shell.Api.ResolveAlertAsync(alert.Id, ResolveNote.Trim());
            ResolveNote = string.Empty;
            InfoMessage = "Resolved. If the problem happens again, a new alert is raised.";
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task SaveRuleAsync() => RunAsync(async () =>
    {
        if (SelectedRule is not { } rule)
        {
            ErrorMessage = "Select a rule in the list first.";
            return;
        }

        if (!int.TryParse(rule.Threshold, out var threshold) || !int.TryParse(rule.WindowMinutes, out var window))
        {
            ErrorMessage = "Enter whole numbers.";
            return;
        }

        await shell.Api.UpdateAlertRuleAsync(rule.Code, new UpdateAlertRuleRequest(rule.Enabled, rule.Severity, threshold, window));
        InfoMessage = $"Rule \"{rule.Name}\" saved. It applies to new alerts within a minute.";
        await FetchAsync();
    });
}
