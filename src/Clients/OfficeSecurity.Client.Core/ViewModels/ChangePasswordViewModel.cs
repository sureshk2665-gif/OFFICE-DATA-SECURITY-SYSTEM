using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Client.Core.ViewModels;

public sealed partial class ChangePasswordViewModel(ApiClient api) : BusyViewModel
{
    [ObservableProperty]
    public partial string CurrentPassword { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewPassword { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ConfirmPassword { get; set; } = string.Empty;

    [RelayCommand]
    private Task ChangeAsync() => RunAsync(async () =>
    {
        InfoMessage = string.Empty;
        if (!PasswordsMatch(NewPassword, ConfirmPassword, out var error))
        {
            ErrorMessage = error;
            return;
        }

        await api.ChangePasswordAsync(new ChangePasswordRequest(CurrentPassword, NewPassword));
        CurrentPassword = NewPassword = ConfirmPassword = string.Empty;
        InfoMessage = "Password changed. Other devices signed in with your account have been signed out.";
    });
}
