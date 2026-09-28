using System.Text.Json;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>
/// Remembers exactly which Windows settings the agent made for each control, so it can tell a setting it
/// made that someone changed (tampering) from one it never touched, and so it only ever removes its own.
/// </summary>
public interface IManagedSettingsStore
{
    IReadOnlyList<PolicyValue> Load(SecurityControl control);

    void Save(SecurityControl control, IReadOnlyList<PolicyValue> values);

    IReadOnlyDictionary<SecurityControl, IReadOnlyList<PolicyValue>> LoadAll();
}

/// <summary>A JSON file in the agent's protected data folder (SYSTEM and Administrators only).</summary>
public sealed class FileManagedSettingsStore(string directory, string fileName = FileManagedSettingsStore.RegistryFile) : IManagedSettingsStore
{
    public const string RegistryFile = "managed-registry-settings.json";
    public const string FirewallFile = "managed-firewall-rules.json";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly Lock _gate = new();

    private string FilePath => Path.Combine(directory, fileName);

    public IReadOnlyList<PolicyValue> Load(SecurityControl control) =>
        LoadAll().TryGetValue(control, out var values) ? values : [];

    public IReadOnlyDictionary<SecurityControl, IReadOnlyList<PolicyValue>> LoadAll()
    {
        lock (_gate)
        {
            return Read().ToDictionary(p => p.Key, p => (IReadOnlyList<PolicyValue>)p.Value.Select(ToValue).ToList());
        }
    }

    public void Save(SecurityControl control, IReadOnlyList<PolicyValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        lock (_gate)
        {
            var all = Read();
            if (values.Count == 0)
            {
                all.Remove(control);
            }
            else
            {
                all[control] = values.Select(v => new StoredValue(v.Key, v.Name, v.Data as int?, v.Data as string)).ToList();
            }

            Directory.CreateDirectory(directory);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(all, Json));
            File.Move(temp, FilePath, overwrite: true);
        }
    }

    private Dictionary<SecurityControl, List<StoredValue>> Read()
    {
        if (!File.Exists(FilePath))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<SecurityControl, List<StoredValue>>>(File.ReadAllText(FilePath), Json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static PolicyValue ToValue(StoredValue v) => new(v.Key, v.Name, (object?)v.Number ?? v.Text ?? string.Empty);

    private sealed record StoredValue(string Key, string Name, int? Number, string? Text);
}

public sealed class InMemoryManagedSettingsStore : IManagedSettingsStore
{
    private readonly Dictionary<SecurityControl, IReadOnlyList<PolicyValue>> _values = [];

    public IReadOnlyList<PolicyValue> Load(SecurityControl control) => _values.GetValueOrDefault(control) ?? [];

    public void Save(SecurityControl control, IReadOnlyList<PolicyValue> values)
    {
        if (values.Count == 0)
        {
            _values.Remove(control);
        }
        else
        {
            _values[control] = [.. values];
        }
    }

    public IReadOnlyDictionary<SecurityControl, IReadOnlyList<PolicyValue>> LoadAll() => _values;
}
