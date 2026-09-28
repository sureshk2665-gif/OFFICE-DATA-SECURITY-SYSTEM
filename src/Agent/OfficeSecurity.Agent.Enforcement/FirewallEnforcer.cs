using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>An outbound "block" rule for one program.</summary>
public sealed record FirewallRule(string Name, string ApplicationPath, bool Enabled, bool IsOutboundBlock);

[Flags]
public enum FirewallProfiles
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
}

/// <summary>Windows Defender Firewall rules, abstracted for tests.</summary>
public interface IFirewall
{
    /// <summary>Profiles whose firewall is turned off.</summary>
    FirewallProfiles DisabledProfiles();

    FirewallRule? Find(string name);

    void AddOutboundBlock(string name, string applicationPath, string description);

    void Remove(string name);
}

/// <summary>
/// Blocks network access for named programs with Windows Defender Firewall outbound rules. The firewall itself
/// is never switched on or off by this system; if it is off, the control reports that the rules have no effect.
/// </summary>
public sealed class FirewallEnforcer(IFirewall firewall, IManagedSettingsStore store, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    public const string RuleGroup = "Office Security System";
    private const string StoreKey = "WindowsFirewall";

    public SecurityControl Control => SecurityControl.NetworkRestrictions;

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var exemption = ActiveExemption(policy, now);
        var desired = exemption is null ? Desired(policy) : [];
        var managed = store.Load(Control);
        var desiredNames = desired.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        store.Save(Control, [.. managed.Where(m => !desiredNames.Contains(m.Name)), .. desired]);

        var restored = new List<string>();
        foreach (var rule in desired)
        {
            var path = (string)rule.Data;
            var current = firewall.Find(rule.Name);
            if (Matches(current, path))
            {
                continue;
            }

            if (managed.Any(m => string.Equals(m.Name, rule.Name, StringComparison.OrdinalIgnoreCase)))
            {
                restored.Add(path);
            }

            if (current is not null)
            {
                firewall.Remove(rule.Name);
            }

            firewall.AddOutboundBlock(rule.Name, path, $"Created by the Office Security System: blocks network access for {path}.");
        }

        foreach (var old in managed.Where(m => !desiredNames.Contains(m.Name)))
        {
            if (firewall.Find(old.Name) is not null)
            {
                firewall.Remove(old.Name);
            }
        }

        store.Save(Control, desired);
        if (restored.Count > 0)
        {
            events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                "Program blocking: Windows Firewall rule(s) had been removed or changed outside this system and were restored for: " + string.Join("; ", restored));
        }

        return Task.FromResult(Status(policy, desired, exemption, now));
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var exemption = ActiveExemption(policy, now);
        return Task.FromResult(Status(policy, exemption is null ? Desired(policy) : [], exemption, now));
    }

    /// <summary>Removes every rule this system created (used when the agent is uninstalled).</summary>
    public static int RemoveAll(IFirewall firewall, IManagedSettingsStore store)
    {
        ArgumentNullException.ThrowIfNull(firewall);
        ArgumentNullException.ThrowIfNull(store);
        var count = 0;
        foreach (var rule in store.Load(SecurityControl.NetworkRestrictions))
        {
            if (firewall.Find(rule.Name) is not null)
            {
                firewall.Remove(rule.Name);
                count++;
            }
        }

        store.Save(SecurityControl.NetworkRestrictions, []);
        return count;
    }

    /// <summary>Stable, readable rule name for a program path.</summary>
    public static string RuleName(string applicationPath)
    {
        ArgumentNullException.ThrowIfNull(applicationPath);
        var file = applicationPath[(applicationPath.LastIndexOf('\\') + 1)..];
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(applicationPath.ToUpperInvariant())))[..8];
        return $"Office Security - block {file} ({hash})";
    }

    private ControlStatus Status(SecurityPolicyDocument policy, List<PolicyValue> desired, PolicyExemption? exemption, DateTimeOffset now)
    {
        var missing = desired.Where(d => !Matches(firewall.Find(d.Name), (string)d.Data)).Select(d => (string)d.Data).ToList();
        if (missing.Count > 0)
        {
            return new ControlStatus(Control, ControlState.Failed, "Firewall rules could not be created for: " + string.Join("; ", missing), now);
        }

        if (exemption is not null)
        {
            return new ControlStatus(Control, ControlState.TemporarilyAllowed,
                string.Create(CultureInfo.InvariantCulture, $"Temporarily allowed by an administrator until {exemption.ExpiresAtUtc:yyyy-MM-dd HH:mm} UTC: {exemption.Reason}"), now);
        }

        var wifi = policy.Network.AllowedWifiNetworks.Count > 0;
        if (desired.Count == 0 && !wifi)
        {
            return new ControlStatus(Control, ControlState.NotConfigured, "Not required by the policy.", now);
        }

        var gaps = new List<string>();
        var off = firewall.DisabledProfiles();
        if (desired.Count > 0 && off != FirewallProfiles.None)
        {
            gaps.Add($"Windows Firewall is turned off for the {off.ToString().Replace(", ", " and ", StringComparison.Ordinal)} network profile(s), so the rules have no effect there");
        }

        if (wifi)
        {
            gaps.Add("restricting Wi-Fi networks is not available yet");
        }

        var done = desired.Count == 0 ? string.Empty : string.Create(CultureInfo.InvariantCulture, $"{desired.Count} program(s) blocked from the network by Windows Firewall. ");
        return gaps.Count == 0
            ? new ControlStatus(Control, ControlState.Enforced, done + "A copy of a program in another folder is not blocked; Application Control covers that.", now)
            : new ControlStatus(Control, desired.Count > 0 ? ControlState.PartiallyEnforced : ControlState.NotImplemented, done + "Not in effect: " + string.Join("; ", gaps) + ".", now);
    }

    private static List<PolicyValue> Desired(SecurityPolicyDocument policy) =>
        policy.Network.BlockedApplicationPaths
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(p => new PolicyValue(StoreKey, RuleName(p), p))
            .ToList();

    private static bool Matches(FirewallRule? rule, string path) =>
        rule is { Enabled: true, IsOutboundBlock: true } && string.Equals(rule.ApplicationPath, path, StringComparison.OrdinalIgnoreCase);

    private PolicyExemption? ActiveExemption(SecurityPolicyDocument policy, DateTimeOffset now) =>
        policy.Exceptions.FirstOrDefault(e => e.Control == Control && e.IsActiveAt(now));
}

/// <summary>
/// Windows Defender Firewall through its documented COM API (HNetCfg.FwPolicy2 / INetFwPolicy2), called
/// through IDispatch.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewall : IFirewall
{
    private const int DirectionOut = 2;   // NET_FW_RULE_DIR_OUT
    private const int ActionBlock = 0;    // NET_FW_ACTION_BLOCK
    private const int AllProfiles = 0x7FFFFFFF; // NET_FW_PROFILE2_ALL
    private const int ElementNotFound = unchecked((int)0x80070002);

    public FirewallProfiles DisabledProfiles()
    {
        var policy = Create("HNetCfg.FwPolicy2");
        var off = FirewallProfiles.None;
        foreach (var profile in new[] { FirewallProfiles.Domain, FirewallProfiles.Private, FirewallProfiles.Public })
        {
            if (!(bool)Get(policy, "FirewallEnabled", (int)profile)!)
            {
                off |= profile;
            }
        }

        return off;
    }

    public FirewallRule? Find(string name)
    {
        var rules = Get(Create("HNetCfg.FwPolicy2"), "Rules")!;
        object rule;
        try
        {
            rule = Call(rules, "Item", name)!;
        }
        catch (COMException ex) when (ex.HResult == ElementNotFound)
        {
            return null;
        }

        return new FirewallRule(
            (string)Get(rule, "Name")!,
            Get(rule, "ApplicationName") as string ?? string.Empty,
            (bool)Get(rule, "Enabled")!,
            (int)Get(rule, "Direction")! == DirectionOut && (int)Get(rule, "Action")! == ActionBlock);
    }

    public void AddOutboundBlock(string name, string applicationPath, string description)
    {
        var rule = Create("HNetCfg.FWRule");
        Set(rule, "Name", name);
        Set(rule, "Description", description);
        Set(rule, "ApplicationName", applicationPath);
        Set(rule, "Direction", DirectionOut);
        Set(rule, "Action", ActionBlock);
        Set(rule, "Profiles", AllProfiles);
        Set(rule, "Grouping", FirewallEnforcer.RuleGroup);
        Set(rule, "Enabled", true);
        Call(Get(Create("HNetCfg.FwPolicy2"), "Rules")!, "Add", rule);
    }

    public void Remove(string name) => Call(Get(Create("HNetCfg.FwPolicy2"), "Rules")!, "Remove", name);

    private static object Create(string progId) =>
        Activator.CreateInstance(Type.GetTypeFromProgID(progId, throwOnError: true)!)!;

    private static object? Get(object target, string property, params object[] args) =>
        target.GetType().InvokeMember(property, BindingFlags.GetProperty, null, target, args, CultureInfo.InvariantCulture);

    private static void Set(object target, string property, object value) =>
        target.GetType().InvokeMember(property, BindingFlags.SetProperty, null, target, [value], CultureInfo.InvariantCulture);

    private static object? Call(object target, string method, params object[] args)
    {
        try
        {
            return target.GetType().InvokeMember(method, BindingFlags.InvokeMethod, null, target, args, CultureInfo.InvariantCulture);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is COMException com)
        {
            throw com;
        }
    }
}

/// <summary>An in-memory firewall for tests.</summary>
public sealed class InMemoryFirewall : IFirewall
{
    public Dictionary<string, FirewallRule> Rules { get; } = new(StringComparer.OrdinalIgnoreCase);

    public FirewallProfiles Disabled { get; set; }

    public FirewallProfiles DisabledProfiles() => Disabled;

    public FirewallRule? Find(string name) => Rules.GetValueOrDefault(name);

    public void AddOutboundBlock(string name, string applicationPath, string description) => Rules[name] = new FirewallRule(name, applicationPath, true, true);

    public void Remove(string name) => Rules.Remove(name);
}
