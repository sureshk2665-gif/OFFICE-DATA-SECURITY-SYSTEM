using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Audit log viewer with search, paging and integrity verification.</summary>
public sealed partial class AuditViewModel(ShellViewModel shell) : SectionViewModel("Audit Logs")
{
    private const int PageSize = 50;

    public ObservableCollection<AuditEntryResponse> Items { get; } = [];

    [ObservableProperty]
    public partial string Search { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int Page { get; set; } = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int TotalCount { get; set; }

    public int TotalPages => Math.Max(1, (TotalCount + PageSize - 1) / PageSize);

    public string PageText => $"Page {Page} of {TotalPages} · {TotalCount} entries";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasVerification))]
    public partial AuditVerificationResponse? Verification { get; set; }

    public bool HasVerification => Verification is not null;

    public override Task ActivateAsync() => LoadAsync();

    [RelayCommand]
    private Task LoadAsync() => RunAsync(async () =>
    {
        var result = await shell.Api.ListAuditAsync(Page, PageSize, Search);
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
    private Task VerifyAsync() => RunAsync(async () => Verification = await shell.Api.VerifyAuditAsync());
}
