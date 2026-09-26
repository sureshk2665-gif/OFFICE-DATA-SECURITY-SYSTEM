using System.Text.Json;

namespace OfficeSecurity.Client.Core;

/// <summary>Per-user settings of a desktop client (not security-sensitive).</summary>
public sealed record ClientSettings
{
    public string ServerAddress { get; init; } = "http://127.0.0.1:5080";

    public static bool TryParseServerAddress(string? value, out Uri? address)
    {
        address = null;
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
        {
            return false;
        }

        address = uri;
        return true;
    }
}

/// <summary>Loads and saves <see cref="ClientSettings"/> as JSON under the user's AppData folder.</summary>
public sealed class ClientSettingsStore(string filePath)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static ClientSettingsStore ForApplication(string applicationName) =>
        new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OfficeSecurity", applicationName, "settings.json"));

    public string FilePath { get; } = filePath;

    public ClientSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath))
            {
                return new ClientSettings();
            }

            using var stream = File.OpenRead(FilePath);
            return JsonSerializer.Deserialize<ClientSettings>(stream, JsonOptions) ?? new ClientSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Corrupt or unreadable settings fall back to defaults instead of preventing start-up.
            return new ClientSettings();
        }
    }

    public void Save(ClientSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, JsonOptions));
        File.Move(temp, FilePath, overwrite: true);
    }
}
