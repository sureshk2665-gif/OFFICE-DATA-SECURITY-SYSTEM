using System.Globalization;
using System.Xml.Linq;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;
using Xunit.Abstractions;

namespace OfficeSecurity.Agent.UnitTests;

/// <summary>
/// Checks every Windows policy value the agent writes against the policy definitions (ADMX) that ship with
/// Windows, so a wrong key, value name or number cannot go unnoticed.
/// </summary>
public sealed class PolicyDefinitionTests(ITestOutputHelper output)
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
    private static readonly string Definitions = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "PolicyDefinitions");

    [WindowsFact]
    public async Task Removable_storage_values_match_the_windows_policy_definitions() =>
        await CheckAsync("RemovableStorage.admx", new RemovableStorageEnforcer(Engine(out var r), NoEnforcementEvents.Instance, TimeProvider.System),
            s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce, BlockOpticalDrives = true } }, r);

    [WindowsFact]
    public async Task Phone_transfer_values_match_the_windows_policy_definitions() =>
        await CheckAsync("RemovableStorage.admx", new MobileDeviceTransferEnforcer(Engine(out var r), NoEnforcementEvents.Instance, TimeProvider.System),
            s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce, BlockPortableDevices = true } }, r);

    [WindowsFact]
    public async Task Software_installation_values_match_the_windows_policy_definitions() =>
        await CheckAsync("MSI.admx|AppxPackageManager.admx", new SoftwareInstallationEnforcer(Engine(out var r), NoEnforcementEvents.Instance, TimeProvider.System),
            s => s with { SoftwareInstallation = new() { BlockStaffInstalls = true } }, r);

    private static RegistryPolicyEngine Engine(out InMemoryPolicyRegistry registry)
    {
        registry = new InMemoryPolicyRegistry();
        return new RegistryPolicyEngine(registry, new InMemoryManagedSettingsStore());
    }

    private async Task CheckAsync(string files, IEnforcer enforcer, Func<PolicySettings, PolicySettings> change, InMemoryPolicyRegistry registry)
    {
        await enforcer.ApplyAsync(change(new PolicySettings()).ToDocument(Guid.NewGuid(), 1, DateTimeOffset.UtcNow), default);
        Assert.NotEmpty(registry.Values);

        var definitions = files.Split('|').SelectMany(Load).ToList();
        foreach (var (id, data) in registry.Values)
        {
            var parts = id.Split('|');
            var match = definitions.FirstOrDefault(d => string.Equals(d.Key, parts[0], StringComparison.OrdinalIgnoreCase)
                && string.Equals(d.ValueName, parts[1], StringComparison.OrdinalIgnoreCase)
                && (d.Value is null || d.Value == (int)data));
            var candidates = definitions.Where(d => string.Equals(d.Key, parts[0], StringComparison.OrdinalIgnoreCase) && string.Equals(d.ValueName, parts[1], StringComparison.OrdinalIgnoreCase))
                .Select(d => $"{d.Value?.ToString(CultureInfo.InvariantCulture) ?? "any number"} = '{d.Display}' (policy {d.Policy})");
            Assert.True(match is not null, $@"HKLM\{parts[0]}\{parts[1]} = {data} is not defined in {files}. Defined: {string.Join(" | ", candidates)}");
            output.WriteLine($@"OK  HKLM\{parts[0]}\{parts[1]} = {data}  →  policy '{match.Policy}': {match.Display}");
        }
    }

    private static IEnumerable<Definition> Load(string file)
    {
        var admx = XDocument.Load(Path.Combine(Definitions, file));
        var adml = XDocument.Load(Path.Combine(Definitions, "en-US", Path.ChangeExtension(file, ".adml")));
        var strings = adml.Descendants(Ns + "string").ToDictionary(s => (string)s.Attribute("id")!, s => s.Value);
        string Text(string? reference) => reference is not null && reference.StartsWith("$(string.", StringComparison.Ordinal)
            ? strings.GetValueOrDefault(reference[9..^1], reference) : reference ?? string.Empty;

        foreach (var policy in admx.Descendants(Ns + "policy"))
        {
            var name = (string)policy.Attribute("name")!;
            var key = (string)policy.Attribute("key")!;
            var display = Text((string?)policy.Attribute("displayName"));
            if ((string?)policy.Attribute("valueName") is { } valueName)
            {
                yield return new Definition(key, valueName, Decimal(policy.Element(Ns + "enabledValue")) ?? 1, name, display);
            }

            foreach (var item in policy.Element(Ns + "enabledList")?.Elements(Ns + "item") ?? [])
            {
                yield return new Definition((string?)item.Attribute("key") ?? key, (string)item.Attribute("valueName")!, Decimal(item.Element(Ns + "value")), name, display);
            }

            foreach (var element in policy.Element(Ns + "elements")?.Elements() ?? [])
            {
                if ((string?)element.Attribute("valueName") is not { } elementValue)
                {
                    continue;
                }

                var elementKey = (string?)element.Attribute("key") ?? key;
                switch (element.Name.LocalName)
                {
                    case "enum":
                        foreach (var item in element.Elements(Ns + "item"))
                        {
                            yield return new Definition(elementKey, elementValue, Decimal(item.Element(Ns + "value")), name, $"{display} = {Text((string?)item.Attribute("displayName"))}");
                        }

                        break;
                    case "boolean":
                        yield return new Definition(elementKey, elementValue, Decimal(element.Element(Ns + "trueValue")) ?? 1, name, display);
                        break;
                    case "decimal":
                        yield return new Definition(elementKey, elementValue, null, name, display);
                        break;
                }
            }
        }
    }

    private static int? Decimal(XElement? value) =>
        value?.Element(Ns + "decimal")?.Attribute("value") is { } v ? int.Parse(v.Value, CultureInfo.InvariantCulture) : null;

    private sealed record Definition(string Key, string ValueName, int? Value, string Policy, string Display);
}

/// <summary>The real registry and firewall on a Windows test machine (under a test key / with test rules only).</summary>
public sealed class WindowsImplementationTests
{
    [WindowsFact]
    public void Registry_values_are_written_read_back_and_deleted()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var root = @"Software\OfficeSecurityTests\" + Guid.NewGuid().ToString("N");
        var registry = new WindowsPolicyRegistry(root);
        var number = new PolicyValue(@"SOFTWARE\Policies\Test", "Deny_Read", 1);
        var text = new PolicyValue(@"SOFTWARE\Policies\Test\URLBlocklist", "1", "example.com");
        try
        {
            var result = new RegistryPolicyEngine(registry, new InMemoryManagedSettingsStore()).Apply(SecurityControl.BrowserRestrictions, [number, text]);

            Assert.True(result.IsVerified);
            Assert.Equal(1, registry.Read(number.Key, number.Name));
            Assert.Equal("example.com", registry.Read(text.Key, text.Name));
            registry.Delete(text.Key, text.Name);
            Assert.Null(registry.Read(text.Key, text.Name));
        }
        finally
        {
            Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(root, throwOnMissingSubKey: false);
        }
    }

    [WindowsFact(requiresAdministrator: true)]
    public void Firewall_rule_is_created_found_and_removed()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var firewall = new WindowsFirewall();
        var path = @"C:\OfficeSecurityTests\" + Guid.NewGuid().ToString("N") + @"\blocked.exe";
        var name = FirewallEnforcer.RuleName(path);
        try
        {
            firewall.AddOutboundBlock(name, path, "Office Security System test rule");
            var rule = firewall.Find(name);

            Assert.NotNull(rule);
            Assert.True(rule.Enabled);
            Assert.True(rule.IsOutboundBlock);
            Assert.Equal(path, rule.ApplicationPath, ignoreCase: true);
            _ = firewall.DisabledProfiles(); // readable
        }
        finally
        {
            if (firewall.Find(name) is not null)
            {
                firewall.Remove(name);
            }
        }

        Assert.Null(firewall.Find(name));
    }
}
