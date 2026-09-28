using System.Globalization;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>Windows Wi-Fi network filters (the "netsh wlan add filter" lists), abstracted for tests.</summary>
public interface IWifi
{
    /// <summary>False when the computer has no Wi-Fi (no WLAN service or adapter).</summary>
    bool Available();

    /// <summary>The Wi-Fi network (SSID) the computer is connected to now, or null.</summary>
    string? ConnectedNetwork();

    /// <summary>Networks on the allow list, and whether all other networks are denied.</summary>
    (IReadOnlyList<string> Allowed, bool DenyAll) Filters();

    void Allow(string ssid);

    void RemoveAllow(string ssid);

    void SetDenyAll(bool deny);
}

/// <summary>
/// Only the office Wi-Fi networks may be used (blocks phone hotspots and other networks). Safety rule: the
/// restriction is never switched on while the computer is connected to a network that is not on the list, so a
/// mistake in the list cannot cut computers off.
/// </summary>
public sealed class WifiRestriction(IWifi wifi, IManagedSettingsStore store, IEnforcementEvents events)
{
    private const string AllowKey = "WifiAllow";
    private const string DenyKey = "WifiDenyAll";

    /// <summary>Returns null when nothing is wanted; otherwise (in force, explanation).</summary>
    public (bool InForce, string Detail)? Apply(IReadOnlyList<string> wanted, bool lifted)
    {
        ArgumentNullException.ThrowIfNull(wanted);
        var managed = store.Load(SecurityControl.NetworkRestrictions);
        var desired = lifted ? [] : wanted.Distinct(StringComparer.Ordinal).ToList();
        if (desired.Count == 0)
        {
            Undo(managed);
            return null;
        }

        if (!wifi.Available())
        {
            Undo(managed);
            return (true, "This computer has no Wi-Fi, so there is nothing to restrict.");
        }

        var (allowed, denyAll) = wifi.Filters();
        var oursDeny = managed.Any(m => m.Key == DenyKey);
        var connected = wifi.ConnectedNetwork();
        if (!(denyAll && oursDeny) && connected is not null && !desired.Contains(connected, StringComparer.Ordinal))
        {
            return (false, $"Not applied yet: the computer is connected to the Wi-Fi network '{connected}', which is not on the allowed list. "
                + "The restriction starts when the computer uses an allowed network or a cable (check the list if this computer is on the office Wi-Fi).");
        }

        store.Save(SecurityControl.NetworkRestrictions, [.. managed, .. desired.Select(s => new PolicyValue(AllowKey, s, 1)), new PolicyValue(DenyKey, "*", 1)]);
        foreach (var ssid in desired.Where(s => !allowed.Contains(s, StringComparer.Ordinal)))
        {
            wifi.Allow(ssid);
        }

        foreach (var old in managed.Where(m => m.Key == AllowKey && !desired.Contains(m.Name, StringComparer.Ordinal)))
        {
            wifi.RemoveAllow(old.Name);
        }

        if (!denyAll)
        {
            if (oursDeny)
            {
                events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "Wi-Fi restriction had been removed outside this system and was restored.");
            }

            wifi.SetDenyAll(true);
        }

        store.Save(SecurityControl.NetworkRestrictions, [.. desired.Select(s => new PolicyValue(AllowKey, s, 1)), new PolicyValue(DenyKey, "*", 1)]);
        var (nowAllowed, nowDenied) = wifi.Filters();
        return nowDenied && desired.All(d => nowAllowed.Contains(d, StringComparer.Ordinal))
            ? (true, string.Create(CultureInfo.InvariantCulture, $"Only these Wi-Fi networks can be used: {string.Join(", ", desired)}."))
            : (false, "The Wi-Fi restriction could not be verified.");
    }

    /// <summary>Removes the filters this system added (used when switched off and on uninstall).</summary>
    public void Undo() => Undo(store.Load(SecurityControl.NetworkRestrictions));

    private void Undo(IReadOnlyList<PolicyValue> managed)
    {
        if (managed.Count == 0)
        {
            return;
        }

        if (wifi.Available())
        {
            if (managed.Any(m => m.Key == DenyKey))
            {
                wifi.SetDenyAll(false);
            }

            foreach (var old in managed.Where(m => m.Key == AllowKey))
            {
                wifi.RemoveAllow(old.Name);
            }
        }

        store.Save(SecurityControl.NetworkRestrictions, []);
    }
}

/// <summary>Bluetooth adapters (radios), abstracted for tests.</summary>
public interface IBluetoothRadios
{
    IReadOnlyList<(string InstanceId, bool Disabled)> Radios();

    void Disable(string instanceId);

    void Enable(string instanceId);
}

/// <summary>
/// Bluetooth: "Disable radio" switches the Bluetooth adapter off (Device Manager "Disable device"); "Block file
/// transfer" blocks Windows' Bluetooth file transfer program (fsquirt.exe) through Application Control, so
/// keyboards, mice and headsets keep working.
/// </summary>
public sealed class BluetoothEnforcer(IBluetoothRadios radios, IManagedSettingsStore store, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    public const string FileTransferProgram = @"%SYSTEM32%\fsquirt.exe";
    private const string Key = "BluetoothRadio";

    public SecurityControl Control => SecurityControl.BluetoothTransfer;

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var managed = store.Load(Control);
        if (policy.Bluetooth.Mode == BluetoothMode.DisableRadio)
        {
            var all = radios.Radios();
            // Only adapters this system switches off are remembered (and switched on again later); one that was
            // already off stays off.
            store.Save(Control, [.. managed, .. all.Where(r => !r.Disabled && !managed.Any(m => m.Name.Equals(r.InstanceId, StringComparison.OrdinalIgnoreCase)))
                .Select(r => new PolicyValue(Key, r.InstanceId, 1))]);
            var restored = new List<string>();
            foreach (var radio in all.Where(r => !r.Disabled))
            {
                if (managed.Any(m => m.Name.Equals(radio.InstanceId, StringComparison.OrdinalIgnoreCase)))
                {
                    restored.Add(radio.InstanceId);
                }

                radios.Disable(radio.InstanceId);
            }

            if (restored.Count > 0)
            {
                events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "A Bluetooth adapter had been switched on again outside this system and was switched off.");
            }
        }
        else
        {
            foreach (var old in managed)
            {
                if (radios.Radios().FirstOrDefault(r => r.InstanceId.Equals(old.Name, StringComparison.OrdinalIgnoreCase)) is { Disabled: true } radio)
                {
                    radios.Enable(radio.InstanceId);
                }
            }

            store.Save(Control, []);
        }

        return VerifyAsync(policy, cancellationToken);
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        ControlStatus S(ControlState state, string detail) => new(Control, state, detail, now);
        switch (policy.Bluetooth.Mode)
        {
            case BluetoothMode.DisableRadio:
                var all = radios.Radios();
                var on = all.Where(r => !r.Disabled).Select(r => r.InstanceId).ToList();
                return Task.FromResult(on.Count > 0
                    ? S(ControlState.Failed, "These Bluetooth adapters could not be switched off: " + string.Join("; ", on))
                    : S(ControlState.Enforced, all.Count == 0
                        ? "No Bluetooth adapter on this computer. One added later is switched off within a minute."
                        : string.Create(CultureInfo.InvariantCulture, $"Bluetooth is switched off ({all.Count} adapter(s) disabled). Bluetooth keyboards, mice and headsets do not work.")));
            case BluetoothMode.BlockFileTransfer:
                return Task.FromResult(policy.ApplicationControl.Mode switch
                {
                    EnforcementMode.Enforce => S(ControlState.PartiallyEnforced,
                        "Windows' Bluetooth file transfer (fsquirt.exe) is blocked by Application Control; keyboards, mice and headsets keep working. "
                        + "Bluetooth programs from the adapter maker that are installed in Program Files are not blocked."),
                    EnforcementMode.Audit => S(ControlState.AuditOnly, "Application Control is in Audit mode: Bluetooth file transfer is reported, not blocked."),
                    _ => S(ControlState.Failed, "Blocking Bluetooth file transfer needs 'Programs staff bring in (Application Control)' set to Enforce in the same policy."),
                });
            default:
                return Task.FromResult(S(ControlState.NotConfigured, "Not required by the policy."));
        }
    }

    /// <summary>Switches back on the adapters this system switched off (used on uninstall).</summary>
    public static int RemoveAll(IBluetoothRadios radios, IManagedSettingsStore store)
    {
        ArgumentNullException.ThrowIfNull(radios);
        ArgumentNullException.ThrowIfNull(store);
        var count = 0;
        foreach (var old in store.Load(SecurityControl.BluetoothTransfer))
        {
            if (radios.Radios().FirstOrDefault(r => r.InstanceId.Equals(old.Name, StringComparison.OrdinalIgnoreCase)) is { Disabled: true } radio)
            {
                radios.Enable(radio.InstanceId);
                count++;
            }
        }

        store.Save(SecurityControl.BluetoothTransfer, []);
        return count;
    }
}

public sealed class InMemoryWifi : IWifi
{
    public bool HasWifi { get; set; } = true;

    public string? Connected { get; set; }

    public List<string> AllowList { get; } = [];

    public bool DenyAllOn { get; set; }

    public bool Available() => HasWifi;

    public string? ConnectedNetwork() => Connected;

    public (IReadOnlyList<string> Allowed, bool DenyAll) Filters() => ([.. AllowList], DenyAllOn);

    public void Allow(string ssid) => AllowList.Add(ssid);

    public void RemoveAllow(string ssid) => AllowList.Remove(ssid);

    public void SetDenyAll(bool deny) => DenyAllOn = deny;
}

public sealed class InMemoryBluetooth : IBluetoothRadios
{
    public Dictionary<string, bool> Adapters { get; } = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<(string InstanceId, bool Disabled)> Radios() => [.. Adapters.Select(a => (a.Key, a.Value))];

    public void Disable(string instanceId) => Adapters[instanceId] = true;

    public void Enable(string instanceId) => Adapters[instanceId] = false;
}
