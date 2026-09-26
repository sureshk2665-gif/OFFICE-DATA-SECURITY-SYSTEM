using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Staff account management: list, search, create, edit, disable/enable and issue setup codes.</summary>
public sealed partial class StaffViewModel(ShellViewModel shell, bool canWrite) : SectionViewModel("Staff Accounts")
{
    private const int PageSize = 25;

    public bool CanWrite { get; } = canWrite;

    public ObservableCollection<StaffSummary> Items { get; } = [];

    public IReadOnlyList<string> StatusFilters { get; } = ["All", "Active", "Waiting for first sign-in", "Disabled"];

    [ObservableProperty]
    public partial string Search { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string StatusFilter { get; set; } = "All";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int Page { get; set; } = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int TotalCount { get; set; }

    public int TotalPages => Math.Max(1, (TotalCount + PageSize - 1) / PageSize);

    public string PageText => $"Page {Page} of {TotalPages} · {TotalCount} staff";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    public partial StaffSummary? Selected { get; set; }

    public bool HasSelection => Selected is not null;

    // ---- create form
    [ObservableProperty]
    public partial bool IsCreateOpen { get; set; }

    [ObservableProperty]
    public partial string NewEmployeeCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewDisplayName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewDepartment { get; set; } = string.Empty;

    // ---- edit form
    [ObservableProperty]
    public partial bool IsEditOpen { get; set; }

    [ObservableProperty]
    public partial string EditDisplayName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string EditDepartment { get; set; } = string.Empty;

    // ---- one-time setup code just issued
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasIssuedCode))]
    public partial SetupCodeResponse? IssuedCode { get; set; }

    public bool HasIssuedCode => IssuedCode is not null;

    public override Task ActivateAsync() => LoadAsync();

    [RelayCommand]
    private Task LoadAsync() => RunAsync(FetchAsync);

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
    private void OpenCreate()
    {
        NewEmployeeCode = NewDisplayName = NewDepartment = string.Empty;
        IsEditOpen = false;
        IsCreateOpen = true;
    }

    [RelayCommand]
    private void CloseForms()
    {
        IsCreateOpen = false;
        IsEditOpen = false;
    }

    [RelayCommand]
    private Task CreateAsync() => RunAsync(async () =>
    {
        IssuedCode = await shell.Api.CreateStaffAsync(new CreateStaffRequest(NewEmployeeCode, NewDisplayName, NewDepartment));
        IsCreateOpen = false;
        await FetchAsync();
    });

    [RelayCommand]
    private void OpenEdit()
    {
        if (Selected is null)
        {
            return;
        }

        EditDisplayName = Selected.DisplayName;
        EditDepartment = Selected.Department ?? string.Empty;
        IsCreateOpen = false;
        IsEditOpen = true;
    }

    [RelayCommand]
    private Task SaveEditAsync() => RunAsync(async () =>
    {
        if (Selected is null)
        {
            return;
        }

        await shell.Api.UpdateStaffAsync(Selected.Id, new UpdateStaffRequest(EditDisplayName, EditDepartment));
        IsEditOpen = false;
        await FetchAsync();
    });

    [RelayCommand]
    private Task DisableAsync() => RunAsync(async () =>
    {
        if (Selected is { } staff && shell.Ui.Confirm("Disable account",
                $"Disable {staff.DisplayName} ({staff.EmployeeCode})? They are signed out immediately and cannot sign in until enabled again."))
        {
            await shell.Api.DisableStaffAsync(staff.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task EnableAsync() => RunAsync(async () =>
    {
        if (Selected is { } staff)
        {
            await shell.Api.EnableStaffAsync(staff.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task ResetAsync() => RunAsync(async () =>
    {
        if (Selected is { } staff && shell.Ui.Confirm("Issue new setup code",
                $"Issue a new setup code for {staff.DisplayName}? Their current password stops working immediately and they must set a new one with the code."))
        {
            IssuedCode = await shell.Api.ResetStaffAsync(staff.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private void CopyCode()
    {
        if (IssuedCode is { } code)
        {
            shell.Ui.CopyToClipboard(code.SetupCode);
        }
    }

    [RelayCommand]
    private void DismissCode() => IssuedCode = null;

    private async Task FetchAsync()
    {
        var status = StatusFilter switch
        {
            "Active" => AccountStatuses.Active,
            "Waiting for first sign-in" => AccountStatuses.PendingActivation,
            "Disabled" => AccountStatuses.Disabled,
            _ => null,
        };
        var result = await shell.Api.ListStaffAsync(Page, PageSize, Search, status);
        Items.Clear();
        foreach (var item in result.Items)
        {
            Items.Add(item);
        }

        TotalCount = result.TotalCount;
        OnPropertyChanged(nameof(TotalPages));
    }
}
