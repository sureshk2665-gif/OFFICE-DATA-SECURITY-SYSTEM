using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Core.ViewModels;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.StaffApp.ViewModels;

/// <summary>Decides which staff screen is shown: connect → sign in / first sign-in → home.</summary>
public sealed partial class StaffShellViewModel : ObservableObject
{
    private readonly ClientSettingsStore _store;
    private ClientSettings _settings;
    private ApiClient? _api;

    public StaffShellViewModel(ClientSettingsStore store, IUiServices ui)
    {
        _store = store;
        Ui = ui;
        _settings = store.Load();
    }

    public IUiServices Ui { get; }

    public ClientSettings Settings => _settings;

    public ApiClient Api => _api ?? throw new InvalidOperationException("Not connected to a server.");

    [ObservableProperty]
    public partial object? Current { get; set; }

    internal void AttachApiForSelfTest(ApiClient api) => _api = api;

    /// <summary>True when connected through the approved security agent on this computer.</summary>
    public bool ConnectedViaAgent { get; private set; }

    /// <summary>
    /// On an approved office computer the staff application uses the agent's server connection, so no
    /// pairing is needed and sign-ins can be tied to this computer. Otherwise it falls back to pairing.
    /// </summary>
    public async Task StartAsync()
    {
        var agent = await AgentLocalClient.TryGetStatusAsync();
        if (agent is { State: "Enrolled", ServerAddress: { } address, CaCertificateBase64: { } ca })
        {
            ConnectedViaAgent = true;
            _settings = new ClientSettings { ServerAddress = address, CaCertificateBase64 = ca };
            _api?.Dispose();
            _api = ApiClient.FromSettings(_settings);
            ShowLogin(info: "Connected to the office server through this computer's security agent.");
            return;
        }

        Start(agent is null ? null : $"This computer's security agent reports: {agent.Message}");
    }

    /// <summary>Asks the agent for a ticket proving this sign-in happens on this computer (null without an agent).</summary>
    public async Task<string?> GetComputerTicketAsync() => ConnectedViaAgent ? await AgentLocalClient.TryGetLoginTicketAsync() : null;

    public void Start(string? notice = null)
    {
        if (!_settings.IsPaired)
        {
            // Connecting the staff application is a one-time task for the person setting up the computer.
            Current = new ConnectViewModel(_store, settings =>
            {
                _settings = settings;
                Start();
            })
            { InfoMessage = notice ?? string.Empty };
            return;
        }

        _api?.Dispose();
        _api = ApiClient.FromSettings(_settings);
        ShowLogin(info: notice);
    }

    public void ShowLogin(string? info = null, string? error = null) =>
        Current = new StaffLoginViewModel(this) { InfoMessage = info ?? string.Empty, ErrorMessage = error ?? string.Empty };

    public void ShowActivate() => Current = new StaffActivateViewModel(this);

    public void ShowHome(CurrentUserResponse user) => Current = new StaffHomeViewModel(this, user);

    public void SessionEnded(string message) => ShowLogin(error: message);

    public async Task SignOutAsync()
    {
        await Api.LogoutAsync();
        ShowLogin(info: "You have signed out.");
    }
}

public sealed partial class StaffLoginViewModel(StaffShellViewModel shell) : BusyViewModel
{
    [ObservableProperty]
    public partial string EmployeeCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [RelayCommand]
    private Task SignInAsync() => RunAsync(async () =>
    {
        InfoMessage = string.Empty;
        var user = await shell.Api.StaffLoginAsync(new StaffLoginRequest(EmployeeCode, Password, await shell.GetComputerTicketAsync()));
        Password = string.Empty;
        shell.ShowHome(user);
    });

    [RelayCommand]
    private void FirstSignIn() => shell.ShowActivate();
}

/// <summary>First sign-in: the staff member sets their own password using the code from the administrator.</summary>
public sealed partial class StaffActivateViewModel(StaffShellViewModel shell) : BusyViewModel
{
    [ObservableProperty]
    public partial string EmployeeCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string SetupCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ConfirmPassword { get; set; } = string.Empty;

    [RelayCommand]
    private Task ActivateAsync() => RunAsync(async () =>
    {
        if (!PasswordsMatch(Password, ConfirmPassword, out var error))
        {
            ErrorMessage = error;
            return;
        }

        var user = await shell.Api.StaffActivateAsync(new StaffActivateRequest(EmployeeCode, SetupCode, Password, await shell.GetComputerTicketAsync()));
        shell.ShowHome(user);
    });

    [RelayCommand]
    private void Back() => shell.ShowLogin();
}

public sealed partial class StaffHomeViewModel(StaffShellViewModel shell, CurrentUserResponse user) : BusyViewModel
{
    public const string SecurityNotice =
        "This computer is protected by the Office Computer Security System. To protect company data, the system may block " +
        "USB storage devices, unapproved software and some file transfers, and it records security events such as blocked " +
        "devices, software installations and sign-ins. It does NOT record your screen, take screenshots, log keystrokes, " +
        "or use the webcam or microphone.";

    public string Greeting { get; } = $"Signed in as {user?.DisplayName} ({user?.LoginName})";

    public ChangePasswordViewModel ChangePassword { get; } = new(shell.Api) { SessionEnded = shell.SessionEnded };

    [RelayCommand]
    private Task SignOutAsync() => shell.SignOutAsync();
}
