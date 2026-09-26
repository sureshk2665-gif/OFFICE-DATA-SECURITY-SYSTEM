using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core.ViewModels;

namespace OfficeSecurity.AdminDashboard.ViewModels;

public sealed partial class SettingsViewModel(ShellViewModel shell) : SectionViewModel("Settings")
{
    public string ServerAddress => shell.Settings.ServerAddress;

    public ChangePasswordViewModel ChangePassword { get; } = new(shell.Api) { SessionEnded = shell.SessionEnded };

    [RelayCommand]
    private async Task ForgetServerAsync()
    {
        if (shell.Ui.Confirm("Change server", "Sign out and disconnect this dashboard from the server? You will need the server address and pairing code to connect again."))
        {
            await shell.Api.LogoutAsync();
            shell.ForgetServer();
        }
    }
}
