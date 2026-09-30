using OfficeSecurity.Client.Core;
using OfficeSecurity.Client.Core.ViewModels;

namespace OfficeSecurity.Client.Core.Tests;

public sealed class PreconfiguredConnectionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ocss-preset-" + Guid.NewGuid().ToString("N"));

    public PreconfiguredConnectionTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Reads_address_and_pairing_code_written_by_setup()
    {
        var file = Path.Combine(_dir, "connection.txt");
        File.WriteAllLines(file, ["localhost", "C117-0E5D-B5FB-B9F7-DB1B", ""]);

        var preset = PreconfiguredConnection.Read(file);

        Assert.Equal(new PreconfiguredConnection("localhost", "C117-0E5D-B5FB-B9F7-DB1B"), preset);
    }

    [Fact]
    public void Missing_or_incomplete_file_gives_nothing()
    {
        Assert.Null(PreconfiguredConnection.Read(Path.Combine(_dir, "missing.txt")));
        var file = Path.Combine(_dir, "connection.txt");
        File.WriteAllText(file, "localhost");
        Assert.Null(PreconfiguredConnection.Read(file));
    }

    [Fact]
    public void Connect_screen_is_filled_in_but_a_saved_address_wins()
    {
        var store = new ClientSettingsStore(Path.Combine(_dir, "settings.json"));
        var preset = new PreconfiguredConnection("localhost", "C117-0E5D-B5FB-B9F7-DB1B");

        var fresh = new ConnectViewModel(store, _ => { }, preset);
        Assert.Equal("localhost", fresh.ServerAddress);
        Assert.Equal("C117-0E5D-B5FB-B9F7-DB1B", fresh.PairingCodeText);

        store.Save(new ClientSettings { ServerAddress = "https://office-pc:5443" });
        Assert.Equal("https://office-pc:5443", new ConnectViewModel(store, _ => { }, preset).ServerAddress);
    }
}
