using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Overview page. Phase 1 shows the live central-server connection only; no statistics are invented.</summary>
public sealed partial class OverviewViewModel : SectionViewModel
{
    private readonly SettingsService _settings;

    public OverviewViewModel(SettingsService settings) : base("Overview")
    {
        _settings = settings;
        _settings.Changed += (_, _) => CheckServerCommand.Execute(null);
    }

    /// <summary><c>null</c> until the first check completes.</summary>
    [ObservableProperty]
    public partial bool? IsServerReachable { get; set; }

    [ObservableProperty]
    public partial string ServerStatusText { get; set; } = "Not checked yet";

    [ObservableProperty]
    public partial string ServerDetails { get; set; } = string.Empty;

    public string ServerAddress => _settings.Current.ServerAddress;

    [RelayCommand]
    private async Task CheckServerAsync()
    {
        OnPropertyChanged(nameof(ServerAddress));
        ServerStatusText = "Checking…";
        var result = await _settings.CreateServerClient().CheckHealthAsync();
        IsServerReachable = result.IsReachable;
        ServerStatusText = result.IsReachable ? "Connected" : "Not reachable";
        ServerDetails = result.IsReachable
            ? $"Server version {result.Health!.ServerVersion} · checked {DateTime.Now:HH:mm:ss}"
            : result.Error ?? string.Empty;
    }
}
