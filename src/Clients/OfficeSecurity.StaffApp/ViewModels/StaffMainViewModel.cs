using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core;

namespace OfficeSecurity.StaffApp.ViewModels;

/// <summary>
/// Staff application main screen. Phase 1: shows the security notice and live server connection.
/// Sign-in (Phase 2) and software requests (Phase 4) are visibly marked as not yet available.
/// </summary>
public sealed partial class StaffMainViewModel : ObservableObject
{
    private readonly ClientSettings _settings;

    public StaffMainViewModel(ClientSettings settings)
    {
        _settings = settings;
        CheckServerCommand.Execute(null);
    }

    public static string SecurityNotice =>
        "This computer is protected by the Office Computer Security System. To protect company data, " +
        "the system may block USB storage devices, unapproved software and some file transfers, and it " +
        "records security events such as blocked devices, software installations and sign-ins. " +
        "It does NOT record your screen, take screenshots, log keystrokes, or use the webcam or microphone.";

    public static string SignInUnavailableText => "Staff sign-in will be available after development Phase 2.";

    public static string RequestUnavailableText => "Software requests will be available after development Phase 4.";

    [ObservableProperty]
    public partial bool? IsServerReachable { get; set; }

    [ObservableProperty]
    public partial string ServerStatusText { get; set; } = "Checking connection…";

    [RelayCommand]
    private async Task CheckServerAsync()
    {
        ServerStatusText = "Checking connection…";
        if (!ClientSettings.TryParseServerAddress(_settings.ServerAddress, out var address))
        {
            IsServerReachable = false;
            ServerStatusText = "Server address is not configured correctly. Contact your administrator.";
            return;
        }

        var result = await ServerClient.Create(address!).CheckHealthAsync();
        IsServerReachable = result.IsReachable;
        ServerStatusText = result.IsReachable
            ? "Connected to the office security server"
            : "Office security server is not reachable";
    }
}
