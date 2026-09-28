using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>What <see cref="RegistryPolicyEngine.Apply"/> changed.</summary>
public sealed record RegistryApplyResult(
    IReadOnlyList<PolicyValue> Written,
    IReadOnlyList<PolicyValue> Restored,
    IReadOnlyList<PolicyValue> ReplacedForeign,
    IReadOnlyList<PolicyValue> Removed,
    IReadOnlyList<PolicyValue> Mismatched)
{
    public bool IsVerified => Mismatched.Count == 0;
}

/// <summary>
/// Writes documented policy values, verifies them by reading them back, and removes only values it wrote
/// itself when they are no longer wanted.
/// </summary>
public sealed class RegistryPolicyEngine(IPolicyRegistry registry, IManagedSettingsStore store)
{
    public RegistryApplyResult Apply(SecurityControl control, IReadOnlyList<PolicyValue> desired)
    {
        ArgumentNullException.ThrowIfNull(desired);
        var managed = store.Load(control);
        var desiredIds = desired.Select(d => d.Id).ToHashSet();

        // Record intent first: if the agent stops half-way, it still knows what it may have written.
        store.Save(control, [.. managed.Where(m => !desiredIds.Contains(m.Id)), .. desired]);

        var written = new List<PolicyValue>();
        var restored = new List<PolicyValue>();
        var foreign = new List<PolicyValue>();
        foreach (var value in desired)
        {
            var current = registry.Read(value.Key, value.Name);
            if (value.HasData(current))
            {
                continue;
            }

            var previous = managed.FirstOrDefault(m => m.Id == value.Id);
            if (previous is not null && previous.HasData(value.Data))
            {
                restored.Add(value); // The agent had set this; someone changed or removed it.
            }
            else if (current is not null)
            {
                foreign.Add(value); // Set by someone else (e.g. an existing Group Policy).
            }

            registry.Write(value);
            written.Add(value);
        }

        var removed = new List<PolicyValue>();
        foreach (var old in managed.Where(m => !desiredIds.Contains(m.Id)))
        {
            // Only remove what is still exactly what the agent wrote.
            if (old.HasData(registry.Read(old.Key, old.Name)))
            {
                registry.Delete(old.Key, old.Name);
                removed.Add(old);
            }
        }

        store.Save(control, desired);
        return new RegistryApplyResult(written, restored, foreign, removed, Verify(desired));
    }

    /// <summary>Values that do not currently have the wanted data.</summary>
    public IReadOnlyList<PolicyValue> Verify(IReadOnlyList<PolicyValue> desired) =>
        desired.Where(d => !d.HasData(registry.Read(d.Key, d.Name))).ToList();

    /// <summary>Removes every value the agent wrote for any control (used when the agent is uninstalled).</summary>
    public int RemoveAll()
    {
        var count = 0;
        foreach (var (control, values) in store.LoadAll().ToList())
        {
            foreach (var value in values.Where(v => v.HasData(registry.Read(v.Key, v.Name))))
            {
                registry.Delete(value.Key, value.Name);
                count++;
            }

            store.Save(control, []);
        }

        return count;
    }
}
