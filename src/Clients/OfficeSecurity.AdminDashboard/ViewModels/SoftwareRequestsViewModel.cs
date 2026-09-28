using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>An installer in the "install this" drop-down of a request.</summary>
public sealed record PackageChoice(Guid Id, string Label);

/// <summary>An approved computer in the "install on" drop-down of a request.</summary>
public sealed record TargetComputerChoice(Guid Id, string Label);

/// <summary>Installation Requests: staff ask for software; an administrator approves (and installs) or rejects.</summary>
public sealed partial class SoftwareRequestsViewModel(ShellViewModel shell, bool canWrite) : SectionViewModel("Installation Requests")
{
    private const int PageSize = 50;

    public bool CanWrite { get; } = canWrite;

    public IReadOnlyList<string> StatusFilters { get; } = ["Waiting for a decision", "Approved", "Rejected", "All"];

    [ObservableProperty]
    public partial string StatusFilter { get; set; } = "Waiting for a decision";

    public ObservableCollection<SoftwareRequestResponse> Items { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(CanDecide))]
    public partial SoftwareRequestResponse? Selected { get; set; }

    public bool HasSelection => Selected is not null;

    public bool CanDecide => CanWrite && Selected?.Status == SoftwareRequestStatuses.Pending;

    public ObservableCollection<PackageChoice> Packages { get; } = [];

    [ObservableProperty]
    public partial PackageChoice? SelectedPackage { get; set; }

    public ObservableCollection<TargetComputerChoice> Computers { get; } = [];

    [ObservableProperty]
    public partial TargetComputerChoice? SelectedComputer { get; set; }

    [ObservableProperty]
    public partial string Note { get; set; } = string.Empty;

    public override Task ActivateAsync() => LoadAsync();

    /// <summary>Used by the start-up self-test to render the decision panel without a server.</summary>
    internal void ShowSampleForSelfTest()
    {
        Items.Add(new SoftwareRequestResponse(Guid.NewGuid(), Guid.NewGuid(), "Sample Person", "EMP001", Guid.NewGuid(), "PC-01", "Contoso Viewer",
            "To open client reports.", SoftwareRequestStatuses.Pending, null, null, DateTimeOffset.UtcNow, null));
        Selected = Items[0];
        Packages.Add(new PackageChoice(Guid.NewGuid(), "Contoso Viewer — viewer.msi"));
        Computers.Add(new TargetComputerChoice(Guid.NewGuid(), "PC-01"));
    }

    [RelayCommand]
    private Task LoadAsync() => RunAsync(FetchAsync);

    [RelayCommand]
    private Task ApproveAsync() => RunAsync(async () =>
    {
        if (Selected is not { } request)
        {
            return;
        }

        if (SelectedPackage is not { } package || SelectedComputer is not { } computer)
        {
            ErrorMessage = "Choose the installer to install and the computer to install it on. Add installers under 'Software Management'.";
            return;
        }

        if (shell.Ui.Confirm("Approve request", $"Approve {request.StaffName}'s request and install {package.Label} on {computer.Label}?"))
        {
            await shell.Api.ApproveSoftwareRequestAsync(request.Id, new ApproveSoftwareRequest(package.Id, computer.Id, NullIfEmpty(Note)));
            InfoMessage = $"Approved. {package.Label} will be installed on {computer.Label} at its next check-in.";
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task RejectAsync() => RunAsync(async () =>
    {
        if (Selected is { } request && shell.Ui.Confirm("Reject request", $"Reject {request.StaffName}'s request for {request.SoftwareName}? They will see your note."))
        {
            await shell.Api.RejectSoftwareRequestAsync(request.Id, NullIfEmpty(Note));
            InfoMessage = "Request rejected.";
            await FetchAsync();
        }
    });

    partial void OnSelectedChanged(SoftwareRequestResponse? value)
    {
        Note = string.Empty;
        SelectedComputer = Computers.FirstOrDefault(c => c.Id == value?.ComputerId);
        SelectedPackage = Packages.FirstOrDefault(p => value is not null && p.Label.StartsWith(value.SoftwareName, StringComparison.OrdinalIgnoreCase));
    }

    private async Task FetchAsync()
    {
        var status = StatusFilter switch
        {
            "Waiting for a decision" => SoftwareRequestStatuses.Pending,
            "Approved" => SoftwareRequestStatuses.Approved,
            "Rejected" => SoftwareRequestStatuses.Rejected,
            _ => null,
        };
        var requests = await shell.Api.ListSoftwareRequestsAsync(1, PageSize, status);
        if (CanWrite)
        {
            var approved = await shell.Api.ListApprovedSoftwareAsync();
            var computers = await shell.Api.ListComputersAsync(1, 200, null, ComputerStatuses.Trusted);
            Packages.Clear();
            foreach (var title in approved)
            {
                foreach (var package in title.Packages)
                {
                    Packages.Add(new PackageChoice(package.Id, $"{title.Name} — {package.FileName}"));
                }
            }

            Computers.Clear();
            foreach (var computer in computers.Items)
            {
                Computers.Add(new TargetComputerChoice(computer.Id, computer.Hostname));
            }
        }

        var selectedId = Selected?.Id;
        Items.Clear();
        foreach (var item in requests.Items)
        {
            Items.Add(item);
        }

        Selected = Items.FirstOrDefault(i => i.Id == selectedId) ?? Items.FirstOrDefault();
    }

    partial void OnStatusFilterChanged(string value) => _ = LoadAsync();

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
