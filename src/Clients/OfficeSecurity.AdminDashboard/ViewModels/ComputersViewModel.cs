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
public sealed partial class ComputersViewModel(ShellViewModel shell, bool canWrite, bool canRevealKeys = false) : SectionViewModel("Computers")
{
    private const int PageSize = 25;

    public bool CanWrite { get; } = canWrite;

    /// <summary>Only super administrators may see BitLocker recovery keys (the server enforces this too).</summary>
    public bool CanRevealKeys { get; } = canRevealKeys;

    // ---- approved USB drives
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanApproveDevice))]
    public partial DeviceSummary? SelectedDevice { get; set; }

    public bool CanApproveDevice => CanWrite && SelectedDevice is { DeviceClass: "DiskDrive" };

    [ObservableProperty]
    public partial string ApproveDeviceDescription { get; set; } = string.Empty;

    public IReadOnlyList<NamedChoice<int>> ApproveDeviceDurations { get; } =
    [
        new(0, "No end date"), new(1, "1 day"), new(7, "1 week"), new(30, "30 days"), new(365, "1 year"),
    ];

    [ObservableProperty]
    public partial NamedChoice<int>? ApproveDeviceDuration { get; set; }

    // ---- BitLocker recovery keys
    public ObservableCollection<RecoveryKeyResponse> RecoveryKeys { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevealSelectedKey))]
    public partial RecoveryKeyResponse? SelectedRecoveryKey { get; set; }

    public bool CanRevealSelectedKey => CanRevealKeys && SelectedRecoveryKey is not null;

    [ObservableProperty]
    public partial string RevealedKeyText { get; set; } = string.Empty;

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
    [NotifyPropertyChangedFor(nameof(HasDetail), nameof(HardwareText), nameof(ControlRows))]
    public partial ComputerDetail? Detail { get; set; }

    /// <summary>The protections this computer reports, most important first.</summary>
    public IReadOnlyList<ControlRow> ControlRows => Detail is null
        ? []
        : Detail.Controls
            .OrderBy(c => c.State switch { ControlState.Failed => 0, ControlState.TemporarilyAllowed => 1, ControlState.NotImplemented => 9, _ => 2 })
            .Select(c => new ControlRow(ControlNames.Of(c.Control), ControlNames.Of(c.State), c.Details, c.State is ControlState.Failed or ControlState.TemporarilyAllowed))
            .ToList();

    // ---- temporary exceptions
    public ObservableCollection<ExemptionResponse> Exemptions { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanEndExemption))]
    public partial ExemptionResponse? SelectedExemption { get; set; }

    public bool CanEndExemption => CanWrite && SelectedExemption is { IsActive: true };

    public IReadOnlyList<NamedChoice<SecurityControl>> ExemptionControls { get; } =
        [.. Contracts.Exemptions.AllowedControls.Select(c => new NamedChoice<SecurityControl>(c, ControlNames.Of(c)))];

    [ObservableProperty]
    public partial NamedChoice<SecurityControl>? ExemptionControl { get; set; }

    public IReadOnlyList<NamedChoice<int>> ExemptionDurations { get; } =
    [
        new(30, "30 minutes"), new(60, "1 hour"), new(120, "2 hours"), new(240, "4 hours"), new(480, "8 hours"), new(1440, "1 day"), new(10080, "1 week"),
    ];

    [ObservableProperty]
    public partial NamedChoice<int>? ExemptionDuration { get; set; }

    [ObservableProperty]
    public partial string ExemptionReason { get; set; } = string.Empty;

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
        Exemptions.Add(new ExemptionResponse(Guid.NewGuid(), detail.Summary.Id, nameof(SecurityControl.RemovableStorage), "Copy scanner files",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(2), DateTimeOffset.UtcNow, "Owner", true, null));
        RecoveryKeys.Add(new RecoveryKeyResponse(1, "C:", "{00000000-0000-0000-0000-000000000000}", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        SelectedDevice = detail.Devices.FirstOrDefault(d => d.DeviceClass == "DiskDrive");
        UninstallCode = new UninstallCodeResponse("U1-SAMPLE", DateTimeOffset.UtcNow.AddHours(24), "OfficeSecurity.Agent.exe uninstall --code U1-SAMPLE");
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
        UninstallCode = null;
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

    // ---- uninstall code
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUninstallCode), nameof(UninstallCommand))]
    public partial UninstallCodeResponse? UninstallCode { get; set; }

    public bool HasUninstallCode => UninstallCode is not null;

    public string UninstallCommand => UninstallCode?.Command ?? string.Empty;

    [RelayCommand]
    private Task UninstallCodeAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer && shell.Ui.Confirm("Uninstall code",
                $"Create a code that allows removing the security agent from {computer.Hostname} during the next 24 hours? This is recorded in the audit log."))
        {
            UninstallCode = await shell.Api.CreateUninstallCodeAsync(computer.Id);
        }
    });

    [RelayCommand]
    private void CopyUninstall() => shell.Ui.CopyToClipboard(UninstallCommand);

    [RelayCommand]
    private void CopyUninstallCode() => shell.Ui.CopyToClipboard(UninstallCode?.Code ?? string.Empty);

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

    [RelayCommand]
    private Task CreateExemptionAsync() => RunAsync(async () =>
    {
        if (Selected is not { } computer || ExemptionControl is not { } control || ExemptionDuration is not { } duration)
        {
            ErrorMessage = "Choose what to allow and for how long.";
            return;
        }

        if (!shell.Ui.Confirm("Temporary exception", $"Allow '{control.Label}' on {computer.Hostname} for {duration.Label}? The protection switches back on automatically afterwards."))
        {
            return;
        }

        var created = await shell.Api.CreateExemptionAsync(computer.Id, new CreateExemptionRequest(control.Value.ToString(), ExemptionReason.Trim(), duration.Value));
        ExemptionReason = string.Empty;
        InfoMessage = $"'{control.Label}' is allowed on {computer.Hostname} until {created.ExpiresAtUtc.ToLocalTime():HH:mm, dd MMM}. The computer applies this at its next check-in.";
        await LoadDetailAsync(computer.Id);
    });

    [RelayCommand]
    private Task EndExemptionAsync() => RunAsync(async () =>
    {
        if (Selected is { } computer && SelectedExemption is { IsActive: true } exemption)
        {
            await shell.Api.EndExemptionAsync(computer.Id, exemption.Id);
            InfoMessage = "Exception ended. The protection switches back on at the computer's next check-in.";
            await LoadDetailAsync(computer.Id);
        }
    });

    /// <summary>
    /// Adds the selected USB drive to the approved devices of the policy this computer uses, so it works on every
    /// computer with that policy (other USB drives stay blocked).
    /// </summary>
    [RelayCommand]
    private Task ApproveDeviceAsync() => RunAsync(async () =>
    {
        if (Selected is not { } computer || Detail is not { } detail || SelectedDevice is not { DeviceClass: "DiskDrive" } device)
        {
            ErrorMessage = "Select a USB drive in the list first.";
            return;
        }

        var description = ApproveDeviceDescription.Trim();
        if (description.Length == 0)
        {
            ErrorMessage = "Enter a description, for example \"Accounts team backup drive (blue)\".";
            return;
        }

        var days = ApproveDeviceDuration?.Value ?? 0;
        var policies = await shell.Api.ListPoliciesAsync();
        var summary = detail.PolicyId is { } pid ? policies.FirstOrDefault(p => p.Id == pid) : policies.FirstOrDefault(p => p.IsDefault);
        if (summary is null)
        {
            ErrorMessage = "The policy of this computer could not be found.";
            return;
        }

        if (!shell.Ui.Confirm("Approve USB drive",
                $"Approve \"{device.Name}\" ({description}) in the policy \"{summary.Name}\"{(days > 0 ? $" for {ApproveDeviceDuration!.Label}" : string.Empty)}?"
                + $"{Environment.NewLine}{Environment.NewLine}It will work on all {summary.ComputerCount} computer(s) using this policy while USB drives are blocked. "
                + "Running programs from it stays blocked. Only approve drives that belong to the company."))
        {
            return;
        }

        var policy = await shell.Api.GetPolicyAsync(summary.Id);
        var storage = policy.Settings.RemovableStorage;
        var approved = storage.ApprovedDevices
            .Where(a => !string.Equals(a.DeviceInstanceId, device.InstanceId, StringComparison.OrdinalIgnoreCase))
            .Append(new ApprovedDevice(device.InstanceId, description, days > 0 ? DateTimeOffset.UtcNow.AddDays(days) : null, device.ParentInstanceId))
            .ToList();
        var settings = policy.Settings with { RemovableStorage = storage with { ApprovedDevices = approved } };
        await shell.Api.UpdatePolicyAsync(policy.Id, new SavePolicyRequest(policy.Name, policy.Description, settings));
        ApproveDeviceDescription = string.Empty;
        InfoMessage = storage.Mode == EnforcementMode.Enforce
            ? $"\"{device.Name}\" approved in \"{policy.Name}\". Computers apply this at their next check-in; reconnect the drive afterwards."
            : $"\"{device.Name}\" approved in \"{policy.Name}\". Note: USB drives are not blocked by this policy yet (mode {storage.Mode}), so the approval has no effect until you set it to Enforce.";
        await LoadDetailAsync(computer.Id);
    });

    [RelayCommand]
    private Task RevealRecoveryKeyAsync() => RunAsync(async () =>
    {
        if (Selected is not { } computer || SelectedRecoveryKey is not { } key || !CanRevealKeys)
        {
            return;
        }

        if (!shell.Ui.Confirm("Show BitLocker recovery key",
                $"Show the recovery key for drive {key.Drive} of {computer.Hostname}? Only do this when someone needs to unlock the drive. "
                + "Your name and the time are recorded in the audit log."))
        {
            return;
        }

        var revealed = await shell.Api.RevealRecoveryKeyAsync(computer.Id, key.Id);
        RevealedKeyText = $"{computer.Hostname} drive {revealed.Drive}: {revealed.RecoveryPassword}";
    });

    [RelayCommand]
    private void HideRecoveryKey() => RevealedKeyText = string.Empty;

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
        var exemptions = await shell.Api.ListExemptionsAsync(id);
        var recoveryKeys = await shell.Api.ListRecoveryKeysAsync(id);
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

        Exemptions.Clear();
        foreach (var x in exemptions)
        {
            Exemptions.Add(x);
        }

        RevealedKeyText = string.Empty;
        RecoveryKeys.Clear();
        foreach (var k in recoveryKeys)
        {
            RecoveryKeys.Add(k);
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
