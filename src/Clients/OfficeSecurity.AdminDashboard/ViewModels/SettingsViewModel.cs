using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core;

namespace OfficeSecurity.AdminDashboard.ViewModels;

public sealed partial class SettingsViewModel : SectionViewModel
{
    private readonly SettingsService _settings;

    public SettingsViewModel(SettingsService settings) : base("Settings")
    {
        _settings = settings;
        ServerAddress = settings.Current.ServerAddress;
    }

    [ObservableProperty]
    public partial string ServerAddress { get; set; }

    [ObservableProperty]
    public partial string Message { get; set; } = string.Empty;

    [RelayCommand]
    private void Save()
    {
        if (!ClientSettings.TryParseServerAddress(ServerAddress, out var address))
        {
            Message = "Enter a full address, for example https://office-server:5443";
            return;
        }

        _settings.Save(_settings.Current with { ServerAddress = address!.ToString().TrimEnd('/') });
        Message = "Saved.";
    }
}
