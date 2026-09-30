using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace OfficeSecurity.Client.Core.ViewModels;

/// <summary>First-time connection to the office server using its address and pairing code.</summary>
public sealed partial class ConnectViewModel(ClientSettingsStore store, Action<ClientSettings> onPaired, PreconfiguredConnection? preset = null) : BusyViewModel
{
    [ObservableProperty]
    public partial string ServerAddress { get; set; } = store?.Load().ServerAddress is { Length: > 0 } saved ? saved : preset?.ServerAddress ?? string.Empty;

    // Filled in by the setup program on the main office computer, so there is nothing to type there.
    [ObservableProperty]
    public partial string PairingCodeText { get; set; } = preset?.PairingCode ?? string.Empty;

    [RelayCommand]
    private Task ConnectAsync() => RunAsync(async () =>
    {
        var result = await PairingService.PairAsync(ServerAddress, PairingCodeText);
        if (!result.Success)
        {
            ErrorMessage = result.Error ?? "Connection failed.";
            return;
        }

        store.Save(result.Settings!);
        onPaired(result.Settings!);
    });
}
