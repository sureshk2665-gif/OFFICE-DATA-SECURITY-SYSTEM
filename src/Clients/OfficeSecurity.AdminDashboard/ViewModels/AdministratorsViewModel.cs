using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Administrator accounts (super administrators only).</summary>
public sealed partial class AdministratorsViewModel(ShellViewModel shell, Guid currentAdminId) : SectionViewModel("Administrators")
{
    public ObservableCollection<AdminSummary> Items { get; } = [];

    public IReadOnlyList<string> Roles { get; } = AdminRoles.All;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChangeSelected))]
    public partial AdminSummary? Selected { get; set; }

    /// <summary>Administrators cannot disable or reset their own account.</summary>
    public bool CanChangeSelected => Selected is not null && Selected.Id != currentAdminId;

    [ObservableProperty]
    public partial bool IsCreateOpen { get; set; }

    [ObservableProperty]
    public partial string NewUsername { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewDisplayName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewRole { get; set; } = AdminRoles.Admin;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasIssuedCode))]
    public partial SetupCodeResponse? IssuedCode { get; set; }

    public bool HasIssuedCode => IssuedCode is not null;

    public override Task ActivateAsync() => LoadAsync();

    [RelayCommand]
    private Task LoadAsync() => RunAsync(FetchAsync);

    [RelayCommand]
    private void OpenCreate()
    {
        NewUsername = NewDisplayName = string.Empty;
        NewRole = AdminRoles.Admin;
        IsCreateOpen = true;
    }

    [RelayCommand]
    private void CloseCreate() => IsCreateOpen = false;

    [RelayCommand]
    private Task CreateAsync() => RunAsync(async () =>
    {
        IssuedCode = await shell.Api.CreateAdminAsync(new CreateAdminRequest(NewUsername, NewDisplayName, NewRole));
        IsCreateOpen = false;
        await FetchAsync();
    });

    [RelayCommand]
    private Task DisableAsync() => RunAsync(async () =>
    {
        if (Selected is { } admin && CanChangeSelected &&
            shell.Ui.Confirm("Disable administrator", $"Disable {admin.DisplayName} ({admin.Username})? They are signed out immediately."))
        {
            await shell.Api.DisableAdminAsync(admin.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task EnableAsync() => RunAsync(async () =>
    {
        if (Selected is { } admin && CanChangeSelected)
        {
            await shell.Api.EnableAdminAsync(admin.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task ResetAsync() => RunAsync(async () =>
    {
        if (Selected is { } admin && CanChangeSelected && shell.Ui.Confirm("Reset administrator",
                $"Reset {admin.DisplayName}'s password and two-step verification (for example after a lost phone)? They must set up again with a new code."))
        {
            IssuedCode = await shell.Api.ResetAdminAsync(admin.Id);
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
        var admins = await shell.Api.ListAdminsAsync();
        Items.Clear();
        foreach (var admin in admins)
        {
            Items.Add(admin);
        }
    }
}
