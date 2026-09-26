namespace OfficeSecurity.Client.Core.Tests;

public sealed class ClientSettingsTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "ocss-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Theory]
    [InlineData("https://office-server:5443", true)]
    [InlineData("http://127.0.0.1:5080", true)]
    [InlineData(" https://office-server:5443 ", true)]
    [InlineData("office-server", false)]
    [InlineData("ftp://office-server", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Server_address_validation(string? value, bool expected) =>
        Assert.Equal(expected, ClientSettings.TryParseServerAddress(value, out _));

    [Fact]
    public void Missing_file_returns_defaults()
    {
        var store = new ClientSettingsStore(Path.Combine(_folder, "settings.json"));

        Assert.Equal(new ClientSettings(), store.Load());
    }

    [Fact]
    public void Saved_settings_are_loaded_back()
    {
        var store = new ClientSettingsStore(Path.Combine(_folder, "settings.json"));
        var settings = new ClientSettings { ServerAddress = "https://office-server:5443" };

        store.Save(settings);

        Assert.Equal(settings, store.Load());
    }

    [Fact]
    public void Corrupt_file_falls_back_to_defaults()
    {
        Directory.CreateDirectory(_folder);
        var path = Path.Combine(_folder, "settings.json");
        File.WriteAllText(path, "{ not json");

        Assert.Equal(new ClientSettings(), new ClientSettingsStore(path).Load());
    }
}
