using System.Globalization;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>A USB mass-storage device known to Windows (connected now or seen before).</summary>
public sealed record StorageDeviceNode(string InstanceId, bool IsPresent);

/// <summary>USB mass-storage devices in Windows' device list (abstracted for tests).</summary>
public interface IUsbStorageDevices
{
    /// <summary>Every device node with the USB mass-storage compatible ID (USB\Class_08), present or not.</summary>
    IReadOnlyList<StorageDeviceNode> List();

    /// <summary>Uninstalls the device node (and its children) so it must be installed again when next plugged in.</summary>
    void Remove(string instanceId);
}

/// <summary>
/// Approved USB drives. Uses Windows' Device Installation Restrictions (DeviceInstallation.admx) with
/// "layered order of evaluation": installing any USB mass-storage device (compatible ID USB\Class_08) is
/// prevented, except the approved devices' instance IDs. Unapproved USB storage devices Windows had already
/// installed are uninstalled, so they cannot be used again either. Used instead of the Removable Storage Access
/// read/write denial when approved devices are listed (that denial cannot make exceptions per device).
/// </summary>
public sealed class ApprovedDevicesEnforcer(RegistryPolicyEngine engine, IUsbStorageDevices devices, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    public const string Key = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
    public const string UsbMassStorage = @"USB\Class_08";

    public SecurityControl Control => SecurityControl.ApprovedDevices;

    /// <summary>The approved devices in force now (USB drive blocking enforced, not lifted by an exception).</summary>
    public static IReadOnlyList<ApprovedDevice> Active(SecurityPolicyDocument policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return policy.RemovableStorage.Mode == EnforcementMode.Enforce
            && !policy.Exceptions.Any(e => e.Control == SecurityControl.RemovableStorage && e.IsActiveAt(now))
            ? policy.RemovableStorage.ApprovedDevices.Where(d => d.IsActiveAt(now)).ToList()
            : [];
    }

    public static HashSet<string> AllowedIds(IEnumerable<ApprovedDevice> approved) =>
        approved.SelectMany(d => new[] { d.DeviceInstanceId, d.ParentInstanceId }).OfType<string>()
            .Select(i => i.Trim()).Where(i => i.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var approved = Active(policy, now);
        var allowed = AllowedIds(approved);
        var result = engine.Apply(Control, Values(allowed));
        if (result.Restored.Count > 0)
        {
            events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                "Approved USB devices: Windows device installation settings had been changed outside this system and were restored.");
        }

        if (allowed.Count > 0 && result.IsVerified)
        {
            var removed = new List<string>();
            foreach (var node in devices.List().Where(n => !allowed.Contains(n.InstanceId)))
            {
                devices.Remove(node.InstanceId);
                removed.Add(node.InstanceId);
            }

            if (removed.Count > 0)
            {
                events.Raise(SecurityEventType.RemovableStorageBlocked, EventSeverities.Warning,
                    string.Create(CultureInfo.InvariantCulture, $"Removed {removed.Count} unapproved USB storage device(s) from Windows; they cannot be installed again while this policy applies: ")
                    + string.Join("; ", removed));
            }
        }

        return Task.FromResult(Status(policy, approved, allowed, result.Mismatched, now));
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var approved = Active(policy, now);
        var allowed = AllowedIds(approved);
        return Task.FromResult(Status(policy, approved, allowed, engine.Verify(Values(allowed)), now));
    }

    private static List<PolicyValue> Values(HashSet<string> allowed)
    {
        if (allowed.Count == 0)
        {
            return [];
        }

        var values = new List<PolicyValue>
        {
            new(Key, "AllowDenyLayered", 1),
            new(Key, "DenyDeviceIDs", 1),
            new($@"{Key}\DenyDeviceIDs", "1", UsbMassStorage),
            new(Key, "AllowInstanceIDs", 1),
        };
        values.AddRange(allowed.Order(StringComparer.OrdinalIgnoreCase).Select((id, i) => new PolicyValue($@"{Key}\AllowInstanceIDs", (i + 1).ToString(CultureInfo.InvariantCulture), id)));
        return values;
    }

    private ControlStatus Status(SecurityPolicyDocument policy, IReadOnlyList<ApprovedDevice> approved, HashSet<string> allowed, IReadOnlyList<PolicyValue> mismatched, DateTimeOffset now)
    {
        if (mismatched.Count > 0)
        {
            return new ControlStatus(Control, ControlState.Failed, "These Windows settings could not be applied: " + string.Join("; ", mismatched.Select(v => v.ToString())), now);
        }

        if (allowed.Count == 0)
        {
            return new ControlStatus(Control, ControlState.NotConfigured,
                policy.RemovableStorage.Mode == EnforcementMode.Enforce ? "No approved USB drives: all USB drives are blocked." : "Not required by the policy.", now);
        }

        var unapproved = devices.List().Count(n => !allowed.Contains(n.InstanceId));
        return unapproved > 0
            ? new ControlStatus(Control, ControlState.Failed, string.Create(CultureInfo.InvariantCulture, $"{unapproved} unapproved USB storage device(s) could not be removed from Windows."), now)
            : new ControlStatus(Control, ControlState.Enforced,
                string.Create(CultureInfo.InvariantCulture, $"Only {approved.Count} approved USB drive(s) can be used: ")
                + string.Join(", ", approved.Select(d => d.Description))
                + ". Windows prevents installing any other USB storage device. Programs cannot be run from any USB drive.", now);
    }
}

public sealed class InMemoryUsbStorageDevices : IUsbStorageDevices
{
    public List<StorageDeviceNode> Nodes { get; } = [];

    public List<string> Removed { get; } = [];

    public IReadOnlyList<StorageDeviceNode> List() => [.. Nodes];

    public void Remove(string instanceId)
    {
        Nodes.RemoveAll(n => n.InstanceId.Equals(instanceId, StringComparison.OrdinalIgnoreCase));
        Removed.Add(instanceId);
    }
}
