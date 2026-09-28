using System.Globalization;

namespace OfficeSecurity.Policy;

/// <summary>Content rules every policy must satisfy, checked when signing and again when verifying.</summary>
public static class PolicyDocumentValidator
{
    public const int MinHeartbeatSeconds = 15;
    public const int MaxHeartbeatSeconds = 3600;
    public const int MaxListEntries = 1000;
    public const int MaxUrlLength = 2048;

    public static IReadOnlyList<string> Validate(SecurityPolicyDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var errors = new List<string>();

        if (document.Version <= 0)
        {
            errors.Add("Version must be positive.");
        }

        if (document.ComputerId == Guid.Empty)
        {
            errors.Add("ComputerId is required.");
        }

        CheckRange(errors, nameof(AgentSettings.HeartbeatIntervalSeconds), document.Agent.HeartbeatIntervalSeconds);
        CheckRange(errors, nameof(AgentSettings.EventUploadIntervalSeconds), document.Agent.EventUploadIntervalSeconds);

        foreach (var device in document.RemovableStorage.ApprovedDevices)
        {
            if (string.IsNullOrWhiteSpace(device.DeviceInstanceId))
            {
                errors.Add("Approved device must have a device instance ID.");
            }

            foreach (var id in new[] { device.DeviceInstanceId, device.ParentInstanceId })
            {
                if (id is not null && (id.Length > 400 || id.Any(char.IsControl) || id.Contains('"', StringComparison.Ordinal)))
                {
                    errors.Add($"Approved device ID '{id}' is not valid.");
                }
            }
        }

        foreach (var hash in document.ApplicationControl.AllowedFileHashes)
        {
            if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
            {
                errors.Add(string.Create(CultureInfo.InvariantCulture, $"'{hash}' is not a SHA-256 hex hash."));
            }
        }

        foreach (var folder in document.FileProtection.ProtectedFolders)
        {
            if (!IsAbsoluteWindowsPath(folder.Path))
            {
                errors.Add($"Protected folder '{folder.Path}' must be an absolute path.");
            }
        }

        foreach (var path in document.Network.BlockedApplicationPaths)
        {
            if (!IsAbsoluteWindowsPath(path))
            {
                errors.Add($"Blocked application '{path}' must be an absolute path.");
            }
        }

        CheckList(errors, "Blocked website", document.Browser.BlockedUrls, MaxUrlLength);
        CheckList(errors, "Allowed website", document.Browser.AllowedUrls, MaxUrlLength);
        CheckList(errors, "Wi-Fi network", document.Network.AllowedWifiNetworks, 32);
        CheckList(errors, "Blocked program", document.Network.BlockedApplicationPaths, 260);
        CheckList(errors, "Allowed program folder", document.ApplicationControl.AllowedFolders, 260);
        foreach (var folder in document.ApplicationControl.AllowedFolders)
        {
            if (!IsAbsoluteWindowsPath(folder.Replace("%OSDRIVE%", "C:", StringComparison.OrdinalIgnoreCase)) || folder.Contains('\'', StringComparison.Ordinal) || folder.Contains('"', StringComparison.Ordinal))
            {
                errors.Add($"Allowed program folder '{folder}' must be a full path such as D:\\CompanyApps\\*.");
            }
        }

        foreach (var exception in document.Exceptions)
        {
            if (exception.ExpiresAtUtc <= exception.StartsAtUtc)
            {
                errors.Add($"Exception {exception.Id} must expire after it starts.");
            }

            if (string.IsNullOrWhiteSpace(exception.Reason))
            {
                errors.Add($"Exception {exception.Id} must have a reason.");
            }
        }

        return errors;
    }

    public static void ThrowIfInvalid(SecurityPolicyDocument document)
    {
        var errors = Validate(document);
        if (errors.Count > 0)
        {
            throw new ArgumentException("Invalid policy: " + string.Join("; ", errors), nameof(document));
        }
    }

    private static void CheckList(List<string> errors, string what, IReadOnlyList<string> values, int maxLength)
    {
        if (values.Count > MaxListEntries)
        {
            errors.Add(string.Create(CultureInfo.InvariantCulture, $"At most {MaxListEntries} entries are allowed for {what.ToLowerInvariant()}s."));
        }

        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > maxLength || value.Any(char.IsControl) || value != value.Trim())
            {
                errors.Add(string.Create(CultureInfo.InvariantCulture, $"{what} '{value}' is not valid (1–{maxLength} characters, no line breaks)."));
            }
        }
    }

    private static void CheckRange(List<string> errors, string name, int seconds)
    {
        if (seconds is < MinHeartbeatSeconds or > MaxHeartbeatSeconds)
        {
            errors.Add(string.Create(CultureInfo.InvariantCulture, $"{name} must be between {MinHeartbeatSeconds} and {MaxHeartbeatSeconds} seconds."));
        }
    }

    // Validated as text so the check behaves the same on the Windows agent and on any build host.
    private static bool IsAbsoluteWindowsPath(string path) =>
        path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'
        || path.StartsWith(@"\\", StringComparison.Ordinal) && path.Length > 2;
}
