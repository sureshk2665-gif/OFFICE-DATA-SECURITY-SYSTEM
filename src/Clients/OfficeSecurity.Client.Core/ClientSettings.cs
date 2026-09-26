using System.Text.Json;

namespace OfficeSecurity.Client.Core;

/// <summary>Per-user connection settings of a desktop client. The CA certificate is public data.</summary>
public sealed record ClientSettings
{
    public const int DefaultPort = 5443;

    /// <summary>Server address, e.g. <c>https://office-server:5443</c>. Empty until the client is paired.</summary>
    public string ServerAddress { get; init; } = string.Empty;

    /// <summary>The server's CA certificate (DER, Base64), pinned during pairing.</summary>
    public string? CaCertificateBase64 { get; init; }

    public bool IsPaired => !string.IsNullOrEmpty(CaCertificateBase64) && TryParseServerAddress(ServerAddress, out _);

    /// <summary>
    /// Accepts what a person is likely to type ("office-pc", "192.168.1.20", "https://office-pc:5443")
    /// and returns a full HTTPS address. Plain HTTP is never accepted.
    /// </summary>
    public static bool TryParseServerAddress(string? value, out Uri? address)
    {
        address = null;
        var text = value?.Trim().TrimEnd('/');
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var hasScheme = text.Contains("://", StringComparison.Ordinal);
        if (!hasScheme)
        {
            text = "https://" + text;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrEmpty(uri.Host) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query))
        {
            return false;
        }

        // No explicit port typed: use the server's default port rather than 443.
        var authority = text[(text.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var portTyped = authority.StartsWith('[') ? authority.Contains("]:", StringComparison.Ordinal) : authority.Contains(':', StringComparison.Ordinal);
        address = new UriBuilder(uri) { Port = portTyped ? uri.Port : DefaultPort, Path = "/" }.Uri;
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
            // Corrupt or unreadable settings fall back to defaults (the user pairs again) instead of preventing start-up.
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
