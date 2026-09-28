using System.Runtime.Versioning;
using Microsoft.Win32;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>One machine-wide policy value: a DWORD (<see cref="int"/>) or a string.</summary>
public sealed record PolicyValue(string Key, string Name, object Data)
{
    public string Id => Key.ToUpperInvariant() + "|" + Name.ToUpperInvariant();

    public bool HasData(object? current) => (Data, current) switch
    {
        (int a, int b) => a == b,
        (string a, string b) => string.Equals(a, b, StringComparison.Ordinal),
        _ => false,
    };

    public override string ToString() => $@"HKLM\{Key}\{Name} = {Data}";
}

/// <summary>Access to the documented policy keys under HKEY_LOCAL_MACHINE, abstracted for tests.</summary>
public interface IPolicyRegistry
{
    /// <summary>The value as <see cref="int"/> (DWORD) or <see cref="string"/>, or null when absent.</summary>
    object? Read(string key, string name);

    void Write(PolicyValue value);

    void Delete(string key, string name);
}

/// <summary>
/// The real registry (64-bit view). Tests pass <paramref name="testRoot"/> so every key is placed under
/// HKEY_CURRENT_USER\{testRoot} instead of HKEY_LOCAL_MACHINE.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPolicyRegistry(string? testRoot = null) : IPolicyRegistry
{
    public object? Read(string key, string name)
    {
        using var k = Root().OpenSubKey(Path(key));
        return k?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) switch
        {
            int i => i,
            string s => s,
            null => null,
            var other => other.ToString(),
        };
    }

    public void Write(PolicyValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var k = Root().CreateSubKey(Path(value.Key), writable: true);
        if (value.Data is int i)
        {
            k.SetValue(value.Name, i, RegistryValueKind.DWord);
        }
        else
        {
            k.SetValue(value.Name, (string)value.Data, RegistryValueKind.String);
        }
    }

    public void Delete(string key, string name)
    {
        using var k = Root().OpenSubKey(Path(key), writable: true);
        k?.DeleteValue(name, throwOnMissingValue: false);
    }

    private RegistryKey Root() => testRoot is null
        ? RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
        : RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);

    private string Path(string key) => testRoot is null ? key : testRoot + "\\" + key;
}

/// <summary>An in-memory registry for tests.</summary>
public sealed class InMemoryPolicyRegistry : IPolicyRegistry
{
    private readonly Dictionary<string, object> _values = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, object> Values => _values;

    public object? Read(string key, string name) => _values.GetValueOrDefault(Id(key, name));

    public void Write(PolicyValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _values[Id(value.Key, value.Name)] = value.Data;
    }

    public void Delete(string key, string name) => _values.Remove(Id(key, name));

    public static string Id(string key, string name) => key.ToUpperInvariant() + "|" + name.ToUpperInvariant();
}
