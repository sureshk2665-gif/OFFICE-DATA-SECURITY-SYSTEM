using OfficeSecurity.Client.Core;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Holds the dashboard's current settings and notifies view models when they change.</summary>
public sealed class SettingsService(ClientSettingsStore store)
{
    public ClientSettings Current { get; private set; } = store.Load();

    public event EventHandler? Changed;

    public void Save(ClientSettings settings)
    {
        store.Save(settings);
        Current = settings;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public ServerClient CreateServerClient() =>
        ClientSettings.TryParseServerAddress(Current.ServerAddress, out var address)
            ? ServerClient.Create(address!)
            : ServerClient.Create(new Uri(new ClientSettings().ServerAddress));
}
