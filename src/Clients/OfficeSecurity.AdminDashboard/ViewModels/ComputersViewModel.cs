using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>A staff member that can be ticked as allowed on the selected computer.</summary>
public sealed partial class StaffChoice(StaffSummary staff, bool selected) : ObservableObject
{
    public Guid Id { get; } = staff.Id;

    public string Label { get; } = $"{staff.DisplayName} ({staff.EmployeeCode})";

    [ObservableProperty]
    public partial bool IsSelected { get; set; } = selected;
}

/// <summary>An entry in the policy drop-down; <see cref="Id"/> null means "default policy".</summary>
public sealed record PolicyChoice(Guid? Id, string Name);

/// <summary>Computers: add (enrollment code), approve, remove, and see status, inventory and assignments.</summary>
public sealed partial class ComputersViewModel(ShellViewModel shell, bool canWrite) : SectionViewModel("Computers")
{
    private const int PageSize = 25;

    public bool CanWrite { get; } = canWrite;

    public ObservableCollection<ComputerSummary> Items { get; } = [];

    public IReadOnlyList<string> StatusFilters { get; } = ["Active and waiting", "Waiting for approval", "Approved", "Removed", "Rejected"];

    [ObservableProperty]
    public partial string Search { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string StatusFilter { get; set; } = "Active and waiting";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int Page { get; set; } = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PageText))]
    public partial int TotalCount { get; set; }

    public int TotalPages => Math.Max(1, (TotalCount + PageSize - 1) / PageSize);

    public string PageText => $"Page {Page} of {TotalPages} · {TotalCount} computers";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(IsSelectedPending), nameof(IsSelectedTrusted))]
    public partial ComputerSummary? Selected { get; set; }

    public bool HasSelection => Selected is not null;

    public bool IsSelectedPending => Selected?.Status == ComputerStatuses.PendingApproval;

    public bool IsSelectedTrusted => Selected?.Status == ComputerStatuses.Trusted;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasDetail), nameof(HardwareText))]
    public partial ComputerDetail? Detail { get; set; }

    public bool HasDetail => Detail is not null;

    public string HardwareText => Detail?.Hardware is { } h
        ? string.Join(Environment.NewLine, new[]
        {
            $"Windows: {h.OsName} {h.OsVersion} (build {h.OsBuild}, edition {h.OsEdition})",
            $"Computer: {h.Manufacturer} {h.Model}, serial {h.SerialNumber}",
            $"Processor: {h.Processor} · Memory: {(h.MemoryMb is { } mb ? $"{mb / 1024.0:0.#} GB" : "?")} · System disk: {(h.SystemDiskGb is { } gb ? $"{gb} GB" : "?")}",
            $"TPM security chip: {(h.TpmPresent switch { true => "present", false => "not found", _ => "unknown" })} · {(h.IsDomainJoined == true ? "Domain" : "Workgroup")}: {h.DomainOrWorkgroup}",
            $"Last address: {Detail.LastSeenIp} · Certificate valid until {Detail.CertificateExpiresAtUtc?.ToLocalTime():dd MMM yyyy}",
        })
        : "No inventory received yet.";

    public ObservableCollection<SecurityEventResponse> RecentEvents { get; } = [];

    public ObservableCollection<InstalledSoftwareResponse> InstalledSoftware { get; } = [];

    public ObservableCollection<DeploymentResponse> Installations { get; } = [];

    public ObservableCollection<PolicyChoice> PolicyChoices { get; } = [];

    [ObservableProperty]
    public partial PolicyChoice? SelectedPolicy { get; set; }

    public ObservableCollection<StaffChoice> StaffChoices { get; } = [];

    // ---- "Add computer" instructions
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasEnrollment), nameof(InstallCommand))]
    public partial EnrollmentCodeResponse? Enrollment { get; set; }

    public bool HasEnrollment => Enrollment is not null;

    public string InstallCommand => Enrollment is null
        ? string.Empty
        : $"OfficeSecurity.Agent.exe install --server {ServerForAgents()} --pairing-code {Enrollment.PairingCode} --enrollment-code {Enrollment.EnrollmentCode}";

    public override Task ActivateAsync() => LoadAsync();

    /// <summary>Used by the start-up self-test to render the detail panel without a server.</summary>
    internal void ShowSampleForSelfTest(ComputerDetail detail, EnrollmentCodeResponse enrollment)
    {
        Detail = detail;
        Enrollment = enrollment;
        RecentEvents.Add(new SecurityEventResponse(1, detail.Summary.Id, detail.Summary.Hostname, "DeviceConnected", EventSeverities.Information, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "sample"));
        PolicyChoices.Add(new PolicyChoice(null, "Default policy (default)"));
        StaffChoices.Add(new StaffChoice(new StaffSummary(Guid.NewGuid(), "EMP001", "Sample", null, AccountStatuses.Active, DateTimeOffset.UtcNow, null, false), true));
        InstalledSoftware.Add(new InstalledSoftwareResponse(detail.Summary.Id, detail.Summary.Hostname, "Free Game", "2.0", "Games Ltd", "User", false, DateTimeOffset.UtcNow));
        Installations.Add(new DeploymentResponse(Guid.NewGuid(), Guid.NewGuid(), "Contoso Viewer", "viewer.msi", detail.Summary.Id, detail.Summary.Hostname, null, "Queued", 0, null, null, DateTimeOffset.UtcNow, null));
    }

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

    partial void OnSelectedChanged(ComputerSummary? value)
    {
        Detail = null;
        if (value is not null)
        {
            _ = RunAsync(() => LoadDetailAsync(value.Id));
        }
    }

    [RelayCommand]
    private Task AddComputerAsync() => RunAsync(async () => Enrollment = await shell.Api.CreateEnrollmentCodeAsync());

    [RelayCommand]
    private void CopyInstallCommand()
    {
        if (HasEnrollment)
        {
            shell.Ui.CopyToClipboard(InstallCommand);
        }
    }

    [RelayCommand]
    private void DismissEnrollment() => Enrollment = null;

    [RelayCommand]
    private Task ApproveAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer && shell.Ui.Confirm("Approve computer",
                $"Approve {computer.Hostname}? Only approve computers you recognise: an approved computer is trusted by the server."))
        {
            await shell.Api.ApproveComputerAsync(computer.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task RejectAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer && shell.Ui.Confirm("Reject computer", $"Reject {computer.Hostname}? It will not be able to connect."))
        {
            await shell.Api.RejectComputerAsync(computer.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task RetireAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer && shell.Ui.Confirm("Remove from management",
                $"Remove {computer.Hostname} from management? The server stops accepting it immediately. To manage it again, install the agent with a new enrollment code."))
        {
            await shell.Api.RetireComputerAsync(computer.Id);
            await FetchAsync();
        }
    });

    [RelayCommand]
    private Task SavePolicyAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer && SelectedPolicy is { } policy)
        {
            await shell.Api.AssignComputerPolicyAsync(computer.Id, policy.Id);
            InfoMessage = $"Policy \"{policy.Name}\" assigned. The computer applies it at its next check-in.";
            await LoadDetailAsync(computer.Id);
        }
    });

    [RelayCommand]
    private Task SaveStaffAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer)
        {
            var assigned = await shell.Api.AssignComputerStaffAsync(computer.Id, StaffChoices.Where(s => s.IsSelected).Select(s => s.Id).ToList());
            InfoMessage = assigned.Count == 0
                ? "No staff restricted to this computer."
                : $"{assigned.Count} staff member(s) may sign in on this computer. They can no longer sign in on computers not assigned to them.";
        }
    });

    private async Task FetchAsync()
    {
        var status = StatusFilter switch
        {
            "Waiting for approval" => ComputerStatuses.PendingApproval,
            "Approved" => ComputerStatuses.Trusted,
            "Removed" => ComputerStatuses.Retired,
            "Rejected" => ComputerStatuses.Rejected,
            _ => null,
        };
        var selectedId = Selected?.Id;
        var result = await shell.Api.ListComputersAsync(Page, PageSize, Search, status);
        Items.Clear();
        foreach (var item in result.Items)
        {
            Items.Add(item);
        }

        TotalCount = result.TotalCount;
        OnPropertyChanged(nameof(TotalPages));
        Selected = Items.FirstOrDefault(i => i.Id == selectedId);
    }

    private async Task LoadDetailAsync(Guid id)
    {
        var detail = await shell.Api.GetComputerAsync(id);
        var events = await shell.Api.ListEventsAsync(1, 20, id, null);
        var policies = await shell.Api.ListPoliciesAsync();
        var staff = await shell.Api.ListStaffAsync(1, 200, null, null);
        var software = await shell.Api.ListInstalledSoftwareAsync(id, null);
        var installations = await shell.Api.ListDeploymentsAsync(1, 20, id, null);
        if (Selected?.Id != id)
        {
            return; // Selection changed while loading.
        }

        Detail = detail;
        InstalledSoftware.Clear();
        foreach (var s in software)
        {
            InstalledSoftware.Add(s);
        }

        Installations.Clear();
        foreach (var d in installations.Items)
        {
            Installations.Add(d);
        }

        RecentEvents.Clear();
        foreach (var e in events.Items)
        {
            RecentEvents.Add(e);
        }

        PolicyChoices.Clear();
        foreach (var p in policies)
        {
            PolicyChoices.Add(new PolicyChoice(p.IsDefault ? null : p.Id, p.IsDefault ? $"{p.Name} (default)" : p.Name));
        }

        SelectedPolicy = PolicyChoices.FirstOrDefault(p => p.Id == detail.PolicyId) ?? PolicyChoices.FirstOrDefault();

        StaffChoices.Clear();
        foreach (var s in staff.Items.Where(s => s.Status != AccountStatuses.Disabled))
        {
            StaffChoices.Add(new StaffChoice(s, detail.AssignedStaff.Any(a => a.Id == s.Id)));
        }
    }

    /// <summary>The server address agents should use: the one this dashboard is connected to.</summary>
    private string ServerForAgents() =>
        ClientSettings.TryParseServerAddress(shell.Settings.ServerAddress, out var uri) ? $"{uri!.Host}:{uri.Port}" : shell.Settings.ServerAddress;
}
