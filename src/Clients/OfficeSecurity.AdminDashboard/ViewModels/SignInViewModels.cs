using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Client.Core.ViewModels;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Creates the first super administrator using the code shown by the server.</summary>
public sealed partial class FirstSetupViewModel(ShellViewModel shell) : BusyViewModel
{
    [ObservableProperty]
    public partial string SetupCode { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Username { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string DisplayName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ConfirmPassword { get; set; } = string.Empty;

    [RelayCommand]
    private Task CreateAsync() => RunAsync(async () =>
    {
        if (!PasswordsMatch(Password, ConfirmPassword, out var error))
        {
            ErrorMessage = error;
            return;
        }

        var enrollment = await shell.Api.SetupFirstAdminAsync(new FirstAdminSetupRequest(SetupCode, Username, DisplayName, Password));
        shell.ShowEnrollment(enrollment);
    });
}

/// <summary>An invited administrator sets a password using the one-time setup code.</summary>
public sealed partial class ActivateAdminViewModel(ShellViewModel shell) : BusyViewModel
{
    [ObservableProperty]
    public partial string Username { get; set; } = string.Empty;

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

        shell.ShowEnrollment(await shell.Api.ActivateAdminAsync(new AdminActivateRequest(Username, SetupCode, Password)));
    });

    [RelayCommand]
    private void Back() => shell.ShowLogin();
}

/// <summary>Adds the account to an authenticator app and confirms it with the first code.</summary>
public sealed partial class MfaEnrollmentViewModel(ShellViewModel shell, MfaEnrollmentResponse enrollment) : BusyViewModel
{
    public string OtpAuthUri { get; } = enrollment?.OtpAuthUri ?? string.Empty;

    /// <summary>Secret in groups of four, for typing into the app when the QR code cannot be scanned.</summary>
    public string SecretForDisplay { get; } = string.Join(' ', (enrollment?.SecretBase32 ?? string.Empty).Chunk(4).Select(c => new string(c)));

    [ObservableProperty]
    public partial string Code { get; set; } = string.Empty;

    [RelayCommand]
    private Task ConfirmAsync() => RunAsync(async () =>
    {
        await shell.Api.ConfirmMfaAsync(new ConfirmMfaRequest(enrollment.EnrollmentTicket, Code));
        shell.ShowLogin(info: "Two-step verification is set up. Sign in with your user name, password and the code from your authenticator app.");
    });
}

/// <summary>Two-step sign-in: password, then authenticator code.</summary>
public sealed partial class LoginViewModel(ShellViewModel shell) : BusyViewModel
{
    private string? _mfaTicket;

    [ObservableProperty]
    public partial string Username { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Code { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPasswordStep))]
    public partial bool IsCodeStep { get; set; }

    public bool IsPasswordStep => !IsCodeStep;

    public string ServerAddress => shell.Settings.ServerAddress;

    [RelayCommand]
    private Task SignInAsync() => RunAsync(async () =>
    {
        InfoMessage = string.Empty;
        var response = await shell.Api.AdminLoginAsync(new Contracts.AdminLoginRequest(Username, Password));
        _mfaTicket = response.MfaTicket;
        Password = string.Empty;
        IsCodeStep = true;
    });

    [RelayCommand]
    private Task VerifyAsync() => RunAsync(async () =>
    {
        try
        {
            var user = await shell.Api.AdminMfaAsync(new AdminMfaRequest(_mfaTicket ?? string.Empty, Code));
            shell.ShowWorkspace(user);
        }
        catch (Client.Core.ApiException) when (_mfaTicket is not null)
        {
            Code = string.Empty;
            throw;
        }
    });

    [RelayCommand]
    private void StartOver()
    {
        _mfaTicket = null;
        Code = string.Empty;
        ErrorMessage = string.Empty;
        IsCodeStep = false;
    }

    [RelayCommand]
    private void Activate() => shell.ShowActivate();

    [RelayCommand]
    private void ChangeServer()
    {
        if (shell.Ui.Confirm("Change server", "Disconnect from this server and connect to a different one?"))
        {
            shell.ForgetServer();
        }
    }
}
