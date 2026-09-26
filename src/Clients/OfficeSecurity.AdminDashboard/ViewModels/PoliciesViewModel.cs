using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Policy;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>
/// Security policies: what each computer should enforce. Policies are signed and delivered to computers now;
/// the Windows enforcement for each setting is built in Phase 5 (computers report "Not implemented" until then).
/// </summary>
public sealed partial class PoliciesViewModel(ShellViewModel shell, bool canWrite) : SectionViewModel("Security Policies")
{
    private Guid? _editingId;
    private PolicySettings _loaded = new();

    public bool CanWrite { get; } = canWrite;

    public ObservableCollection<PolicySummary> Items { get; } = [];

    public IReadOnlyList<EnforcementMode> EnforcementModes { get; } = Enum.GetValues<EnforcementMode>();

    public IReadOnlyList<BluetoothMode> BluetoothModes { get; } = Enum.GetValues<BluetoothMode>();

    [ObservableProperty]
    public partial PolicySummary? Selected { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EditorTitle), nameof(CanDelete))]
    public partial bool IsEditing { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDelete))]
    public partial bool EditingDefault { get; set; }

    public string EditorTitle => _editingId is null ? "New policy" : "Edit policy";

    public bool CanDelete => CanWrite && IsEditing && _editingId is not null && !EditingDefault;

    [ObservableProperty]
    public partial string Name { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Description { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int HeartbeatSeconds { get; set; } = 60;

    [ObservableProperty]
    public partial EnforcementMode RemovableStorageMode { get; set; }

    [ObservableProperty]
    public partial bool BlockPortableDevices { get; set; } = true;

    [ObservableProperty]
    public partial bool BlockOpticalDrives { get; set; } = true;

    [ObservableProperty]
    public partial BluetoothMode BluetoothMode { get; set; }

    [ObservableProperty]
    public partial EnforcementMode ApplicationControlMode { get; set; }

    [ObservableProperty]
    public partial bool BlockUserWritableLocations { get; set; } = true;

    [ObservableProperty]
    public partial bool DisablePrivateBrowsing { get; set; }

    [ObservableProperty]
    public partial string BlockedUrls { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string AllowedUrls { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string AllowedWifiNetworks { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string BlockedApplications { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ProtectedFolders { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool AuditProtectedFolders { get; set; } = true;

    [ObservableProperty]
    public partial bool RansomwareProtection { get; set; }

    public override Task ActivateAsync() => LoadAsync();

    [RelayCommand]
    private Task LoadAsync() => RunAsync(FetchAsync);

    partial void OnSelectedChanged(PolicySummary? value)
    {
        if (value is not null)
        {
            _ = RunAsync(async () => Edit(await shell.Api.GetPolicyAsync(value.Id)));
        }
    }

    [RelayCommand]
    private void New()
    {
        Selected = null;
        _editingId = null;
        EditingDefault = false;
        Fill(string.Empty, string.Empty, new PolicySettings());
        IsEditing = true;
        OnPropertyChanged(nameof(EditorTitle));
    }

    [RelayCommand]
    private Task SaveAsync() => RunAsync(async () =>
    {
        InfoMessage = string.Empty;
        var request = new SavePolicyRequest(Name, Description, BuildSettings());
        var saved = _editingId is { } id
            ? await shell.Api.UpdatePolicyAsync(id, request)
            : await shell.Api.CreatePolicyAsync(request);
        InfoMessage = $"Policy \"{saved.Name}\" saved (revision {saved.Revision}). Computers using it receive the new version at their next check-in.";
        await FetchAsync();
        Selected = Items.FirstOrDefault(p => p.Id == saved.Id);
    });

    [RelayCommand]
    private Task DeleteAsync() => RunAsync(async () =>
    {
        if (_editingId is { } id && shell.Ui.Confirm("Delete policy", $"Delete the policy \"{Name}\"?"))
        {
            await shell.Api.DeletePolicyAsync(id);
            IsEditing = false;
            InfoMessage = "Policy deleted.";
            await FetchAsync();
        }
    });

    private async Task FetchAsync()
    {
        var policies = await shell.Api.ListPoliciesAsync();
        Items.Clear();
        foreach (var p in policies)
        {
            Items.Add(p);
        }
    }

    private void Edit(PolicyDetail detail)
    {
        _editingId = detail.Id;
        EditingDefault = detail.IsDefault;
        Fill(detail.Name, detail.Description ?? string.Empty, detail.Settings);
        IsEditing = true;
        OnPropertyChanged(nameof(EditorTitle));
        OnPropertyChanged(nameof(CanDelete));
    }

    private void Fill(string name, string description, PolicySettings s)
    {
        _loaded = s;
        Name = name;
        Description = description;
        HeartbeatSeconds = s.Agent.HeartbeatIntervalSeconds;
        RemovableStorageMode = s.RemovableStorage.Mode;
        BlockPortableDevices = s.RemovableStorage.BlockPortableDevices;
        BlockOpticalDrives = s.RemovableStorage.BlockOpticalDrives;
        BluetoothMode = s.Bluetooth.Mode;
        ApplicationControlMode = s.ApplicationControl.Mode;
        BlockUserWritableLocations = s.ApplicationControl.BlockUserWritableLocations;
        DisablePrivateBrowsing = s.Browser.DisablePrivateBrowsing;
        BlockedUrls = Lines(s.Browser.BlockedUrls);
        AllowedUrls = Lines(s.Browser.AllowedUrls);
        AllowedWifiNetworks = Lines(s.Network.AllowedWifiNetworks);
        BlockedApplications = Lines(s.Network.BlockedApplicationPaths);
        ProtectedFolders = Lines(s.FileProtection.ProtectedFolders.Select(f => f.Path));
        AuditProtectedFolders = s.FileProtection.ProtectedFolders.Count == 0 || s.FileProtection.ProtectedFolders.Any(f => f.AuditAccess);
        RansomwareProtection = s.FileProtection.ProtectedFolders.Any(f => f.ControlledFolderAccess);
    }

    /// <summary>Settings not shown in this editor (approved devices, allow-lists, exemptions) are kept unchanged.</summary>
    private PolicySettings BuildSettings() => _loaded with
    {
        Agent = _loaded.Agent with { HeartbeatIntervalSeconds = HeartbeatSeconds },
        RemovableStorage = _loaded.RemovableStorage with { Mode = RemovableStorageMode, BlockPortableDevices = BlockPortableDevices, BlockOpticalDrives = BlockOpticalDrives },
        Bluetooth = _loaded.Bluetooth with { Mode = BluetoothMode },
        ApplicationControl = _loaded.ApplicationControl with { Mode = ApplicationControlMode, BlockUserWritableLocations = BlockUserWritableLocations },
        Browser = _loaded.Browser with { DisablePrivateBrowsing = DisablePrivateBrowsing, BlockedUrls = Split(BlockedUrls), AllowedUrls = Split(AllowedUrls) },
        Network = _loaded.Network with { AllowedWifiNetworks = Split(AllowedWifiNetworks), BlockedApplicationPaths = Split(BlockedApplications) },
        FileProtection = new FileProtectionSettings
        {
            ProtectedFolders = Split(ProtectedFolders).Select(p => new ProtectedFolder(p, AuditProtectedFolders, RansomwareProtection)).ToList(),
        },
    };

    private static string Lines(IEnumerable<string> values) => string.Join(Environment.NewLine, values);

    private static List<string> Split(string text) =>
        text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
