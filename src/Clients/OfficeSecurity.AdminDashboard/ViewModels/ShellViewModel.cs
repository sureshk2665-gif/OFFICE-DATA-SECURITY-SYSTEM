using CommunityToolkit.Mvvm.ComponentModel;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Core.ViewModels;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>
/// Decides which screen the dashboard shows: connect → first-time setup or sign-in → workspace.
/// </summary>
public sealed partial class ShellViewModel : ObservableObject
{
    private readonly ClientSettingsStore _store;
    private ClientSettings _settings;
    private ApiClient? _api;

    public ShellViewModel(ClientSettingsStore store, IUiServices ui)
    {
        _store = store;
        Ui = ui;
        _settings = store.Load();
    }

    public IUiServices Ui { get; }

    public ClientSettings Settings => _settings;

    [ObservableProperty]
    public partial object? Current { get; set; }

    public ApiClient Api => _api ?? throw new InvalidOperationException("Not connected to a server.");

    /// <summary>Used by the start-up self-test to build screens without contacting a server.</summary>
    internal void AttachApiForSelfTest(ApiClient api) => _api = api;

    /// <summary>Called once the window is shown.</summary>
    public async Task StartAsync()
    {
        if (!_settings.IsPaired)
        {
            ShowConnect();
            return;
        }

        _api?.Dispose();
        _api = ApiClient.FromSettings(_settings);
        try
        {
            var status = await _api.GetSetupStatusAsync();
            if (status.FirstAdminSetupRequired)
            {
                Current = new FirstSetupViewModel(this);
            }
            else
            {
                ShowLogin();
            }
        }
        catch (ApiException ex)
        {
            ShowLogin(error: ex.Message);
        }
    }

    public void ShowConnect() => Current = new ConnectViewModel(_store, settings =>
    {
        _settings = settings;
        _ = StartAsync();
    });

    public void ShowLogin(string? info = null, string? error = null) =>
        Current = new LoginViewModel(this) { InfoMessage = info ?? string.Empty, ErrorMessage = error ?? string.Empty };

    public void ShowActivate() => Current = new ActivateAdminViewModel(this);

    public void ShowEnrollment(MfaEnrollmentResponse enrollment) => Current = new MfaEnrollmentViewModel(this, enrollment);

    public void ShowWorkspace(CurrentUserResponse user) => Current = new WorkspaceViewModel(this, user);

    public void SessionEnded(string message) => ShowLogin(error: message);

    public async Task SignOutAsync()
    {
        await Api.LogoutAsync();
        ShowLogin(info: "You have signed out.");
    }

    public void ForgetServer()
    {
        _store.Save(new ClientSettings { ServerAddress = _settings.ServerAddress });
        _settings = _store.Load();
        _api?.Dispose();
        _api = null;
        ShowConnect();
    }
}
