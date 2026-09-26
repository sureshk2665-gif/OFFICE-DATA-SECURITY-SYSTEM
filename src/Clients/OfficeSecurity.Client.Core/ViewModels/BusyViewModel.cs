using System.Net;
using CommunityToolkit.Mvvm.ComponentModel;

namespace OfficeSecurity.Client.Core.ViewModels;

/// <summary>Base for screens that call the server: tracks busy state and shows friendly errors.</summary>
public abstract partial class BusyViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsNotBusy))]
    public partial bool IsBusy { get; set; }

    public bool IsNotBusy => !IsBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    public partial string ErrorMessage { get; set; } = string.Empty;

    public bool HasError => ErrorMessage.Length > 0;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasInfo))]
    public partial string InfoMessage { get; set; } = string.Empty;

    public bool HasInfo => InfoMessage.Length > 0;

    /// <summary>Called when a signed-in call is rejected because the session ended.</summary>
    public Action<string>? SessionEnded { get; set; }

    protected async Task RunAsync(Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (IsBusy)
        {
            return;
        }

        ErrorMessage = string.Empty;
        IsBusy = true;
        try
        {
            await action();
        }
        catch (ApiException ex)
        {
            if (ex.StatusCode == HttpStatusCode.Unauthorized && SessionEnded is not null)
            {
                SessionEnded(ex.Message);
            }
            else
            {
                ErrorMessage = ex.Message;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    protected static bool PasswordsMatch(string password, string confirmation, out string error)
    {
        error = string.Equals(password, confirmation, StringComparison.Ordinal) ? string.Empty : "The two passwords do not match.";
        return error.Length == 0;
    }
}
