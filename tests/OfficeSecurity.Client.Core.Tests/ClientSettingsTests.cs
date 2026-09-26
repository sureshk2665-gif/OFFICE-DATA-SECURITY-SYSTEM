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
    [InlineData("https://office-server:5443", "https://office-server:5443/")]
    [InlineData(" https://office-server:5443/ ", "https://office-server:5443/")]
    [InlineData("office-server", "https://office-server:5443/")]
    [InlineData("192.168.1.20", "https://192.168.1.20:5443/")]
    [InlineData("192.168.1.20:7000", "https://192.168.1.20:7000/")]
    [InlineData("https://office-server", "https://office-server:5443/")]
    [InlineData("https://office-server:443", "https://office-server/")]
    public void Server_address_is_normalized_to_https(string input, string expected)
    {
        Assert.True(ClientSettings.TryParseServerAddress(input, out var address));
        Assert.Equal(expected, address!.ToString());
    }

    [Theory]
    [InlineData("http://office-server:5443")]
    [InlineData("ftp://office-server")]
    [InlineData("https://office-server/path")]
    [InlineData("")]
    [InlineData(null)]
    public void Insecure_or_invalid_addresses_are_rejected(string? input) =>
        Assert.False(ClientSettings.TryParseServerAddress(input, out _));

    [Fact]
    public void Settings_without_pinned_certificate_are_not_paired() =>
        Assert.False(new ClientSettings { ServerAddress = "https://office-server:5443" }.IsPaired);

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
        var settings = new ClientSettings { ServerAddress = "https://office-server:5443", CaCertificateBase64 = "AQID" };

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
