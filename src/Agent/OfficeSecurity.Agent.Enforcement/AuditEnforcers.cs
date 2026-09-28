using System.Globalization;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>Windows advanced audit policy (Local Security Policy > Advanced Audit Policy Configuration).</summary>
public interface IAuditPolicy
{
    /// <summary>1 = success, 2 = failure (flags); 0 = not audited.</summary>
    int Query(Guid subcategory);

    void Change(Guid subcategory, bool success, bool failure);
}

/// <summary>Audit entries (SACL) on folders: "record who reads, changes or deletes files here".</summary>
public interface IFolderAudit
{
    bool Exists(string folder);

    bool HasRule(string folder);

    void AddRule(string folder);

    void RemoveRule(string folder);
}

public static class AuditSubcategories
{
    public static readonly Guid Logon = new("0CCE9215-69AE-11D9-BED3-505054503030");
    public static readonly Guid Logoff = new("0CCE9216-69AE-11D9-BED3-505054503030");
    public static readonly Guid FileSystem = new("0CCE921D-69AE-11D9-BED3-505054503030");

    public const int SuccessAndFailure = 3;
}

/// <summary>
/// Switches on Windows audit subcategories, remembering the previous setting so it can be put back, and
/// restoring them if someone switches them off.
/// </summary>
public sealed class AuditPolicyEngine(IAuditPolicy audit, IManagedSettingsStore store)
{
    private const string Key = "AuditPolicy";

    /// <summary>Returns the subcategories that had been switched off by someone else and were restored.</summary>
    public IReadOnlyList<Guid> Apply(SecurityControl control, IReadOnlyList<Guid> wanted)
    {
        ArgumentNullException.ThrowIfNull(wanted);
        var all = store.Load(control);
        var managed = all.Where(v => v.Key == Key).ToList();
        var others = all.Where(v => v.Key != Key).ToList();
        var restored = new List<Guid>();
        var result = new List<PolicyValue>();

        foreach (var g in wanted)
        {
            var previous = managed.FirstOrDefault(m => Guid.Parse(m.Name) == g);
            var current = audit.Query(g);
            var original = previous is null ? current : (int)previous.Data;
            result.Add(new PolicyValue(Key, g.ToString("D"), original));
            if ((current & AuditSubcategories.SuccessAndFailure) != AuditSubcategories.SuccessAndFailure)
            {
                if (previous is not null)
                {
                    restored.Add(g);
                }

                store.Save(control, [.. others, .. result, .. managed.Where(m => !wanted.Contains(Guid.Parse(m.Name)))]);
                audit.Change(g, success: true, failure: true);
            }
        }

        foreach (var old in managed.Where(m => !wanted.Contains(Guid.Parse(m.Name))))
        {
            var g = Guid.Parse(old.Name);
            if ((audit.Query(g) & AuditSubcategories.SuccessAndFailure) == AuditSubcategories.SuccessAndFailure)
            {
                var original = (int)old.Data;
                audit.Change(g, success: (original & 1) != 0, failure: (original & 2) != 0);
            }
        }

        store.Save(control, [.. others, .. result]);
        return restored;
    }

    /// <summary>Puts back every audit setting this system changed (used when the agent is uninstalled).</summary>
    public int RemoveAll()
    {
        var count = 0;
        foreach (var control in store.LoadAll().Keys.ToList())
        {
            count += store.Load(control).Count(v => v.Key == Key);
            Apply(control, []);
        }

        return count;
    }

    public bool IsOn(Guid subcategory) => (audit.Query(subcategory) & AuditSubcategories.SuccessAndFailure) == AuditSubcategories.SuccessAndFailure;
}

/// <summary>Windows sign-in records: sign-ins, failed sign-ins and sign-outs on the computer are reported.</summary>
public sealed class SignInAuditEnforcer(AuditPolicyEngine engine, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    private static readonly Guid[] Needed = [AuditSubcategories.Logon, AuditSubcategories.Logoff];

    public SecurityControl Control => SecurityControl.LoginAudit;

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var on = policy.SignInAudit.RecordWindowsSignIns;
        var restored = engine.Apply(Control, on ? Needed : []);
        if (restored.Count > 0)
        {
            events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, "Windows sign-in auditing had been switched off outside this system and was switched back on.");
        }

        return VerifyAsync(policy, cancellationToken);
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        if (!policy.SignInAudit.RecordWindowsSignIns)
        {
            return Task.FromResult(new ControlStatus(Control, ControlState.NotConfigured, "Not required by the policy.", now));
        }

        return Task.FromResult(Needed.All(engine.IsOn)
            ? new ControlStatus(Control, ControlState.Enforced, "Windows records sign-ins, failed sign-ins and sign-outs (Logon/Logoff auditing); the agent reports them to the server.", now)
            : new ControlStatus(Control, ControlState.Failed, "Windows Logon/Logoff auditing could not be switched on.", now));
    }
}

/// <summary>
/// Records who reads, changes or deletes files in the protected folders: turns on "File System" auditing and puts
/// an audit entry on each folder. The agent reports the resulting Windows events.
/// </summary>
public sealed class FileAccessAuditEnforcer(AuditPolicyEngine engine, IFolderAudit folders, IManagedSettingsStore store, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    private const string Key = "FolderAudit";

    public SecurityControl Control => SecurityControl.FileAccessAudit;

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var wanted = Wanted(policy);
        var restoredAudit = engine.Apply(Control, wanted.Count > 0 ? [AuditSubcategories.FileSystem] : []);

        var all = store.Load(Control);
        var managed = all.Where(v => v.Key == Key).ToList();
        var others = all.Where(v => v.Key != Key).ToList();
        var restored = new List<string>();
        var desired = wanted.Where(folders.Exists).Select(f => new PolicyValue(Key, f, 1)).ToList();
        store.Save(Control, [.. others, .. managed.Where(m => !desired.Any(d => d.Id == m.Id)), .. desired]);
        foreach (var value in desired.Where(d => !folders.HasRule(d.Name)))
        {
            if (managed.Any(m => m.Id == value.Id))
            {
                restored.Add(value.Name);
            }

            folders.AddRule(value.Name);
        }

        foreach (var old in managed.Where(m => !desired.Any(d => d.Id == m.Id)))
        {
            if (folders.Exists(old.Name) && folders.HasRule(old.Name))
            {
                folders.RemoveRule(old.Name);
            }
        }

        store.Save(Control, [.. store.Load(Control).Where(v => v.Key != Key), .. desired]);
        if (restoredAudit.Count > 0 || restored.Count > 0)
        {
            events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                "File access records had been switched off outside this system and were switched back on" + (restored.Count > 0 ? " for: " + string.Join("; ", restored) : "."));
        }

        return VerifyAsync(policy, cancellationToken);
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var wanted = Wanted(policy);
        if (wanted.Count == 0)
        {
            return Task.FromResult(new ControlStatus(Control, ControlState.NotConfigured, "Not required by the policy.", now));
        }

        var missing = wanted.Where(f => !folders.Exists(f)).ToList();
        var notAudited = wanted.Except(missing).Where(f => !folders.HasRule(f)).ToList();
        if (!engine.IsOn(AuditSubcategories.FileSystem) || notAudited.Count > 0)
        {
            return Task.FromResult(new ControlStatus(Control, ControlState.Failed,
                "File access auditing could not be switched on" + (notAudited.Count > 0 ? " for: " + string.Join("; ", notAudited) : "."), now));
        }

        var done = string.Create(CultureInfo.InvariantCulture, $"Who reads, changes or deletes files is recorded for {wanted.Count - missing.Count} folder(s).");
        return Task.FromResult(missing.Count == 0
            ? new ControlStatus(Control, ControlState.Enforced, done + " It records that a file was opened, not where its content went afterwards.", now)
            : new ControlStatus(Control, ControlState.PartiallyEnforced, done + " These folders do not exist on this computer: " + string.Join("; ", missing), now));
    }

    /// <summary>Removes the folder audit entries this system added (used when the agent is uninstalled).</summary>
    public static int RemoveAll(IFolderAudit folders, IManagedSettingsStore store)
    {
        ArgumentNullException.ThrowIfNull(folders);
        ArgumentNullException.ThrowIfNull(store);
        var count = 0;
        var managed = store.Load(SecurityControl.FileAccessAudit);
        foreach (var value in managed.Where(v => v.Key == Key && folders.Exists(v.Name) && folders.HasRule(v.Name)))
        {
            folders.RemoveRule(value.Name);
            count++;
        }

        store.Save(SecurityControl.FileAccessAudit, [.. managed.Where(v => v.Key != Key)]);
        return count;
    }

    private static List<string> Wanted(SecurityPolicyDocument policy) =>
        policy.FileProtection.ProtectedFolders.Where(f => f.AuditAccess).Select(f => f.Path.TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}

/// <summary>Microsoft Defender Antivirus state, needed for ransomware protection.</summary>
public interface IDefenderStatus
{
    /// <summary>Null when Defender is the active antivirus with real-time protection; otherwise why not.</summary>
    string? InactiveReason();

    /// <summary>Controlled Folder Access mode Defender reports as in effect (0 off, 1 block, 2 audit), or null.</summary>
    int? EffectiveControlledFolderAccess();
}

/// <summary>
/// Ransomware protection with Microsoft Defender "Controlled Folder Access" (WindowsDefender.admx): only trusted
/// programs may change files in the protected folders.
/// </summary>
public sealed class ControlledFolderAccessEnforcer(RegistryPolicyEngine engine, IDefenderStatus defender, IEnforcementEvents events, TimeProvider clock)
    : RegistryPolicyEnforcer(engine, events, clock)
{
    public const string Key = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";

    public override SecurityControl Control => SecurityControl.ControlledFolderAccess;

    protected override string Description => "Ransomware protection";

    protected override RegistryPlan Plan(SecurityPolicyDocument policy)
    {
        var protectedFolders = policy.FileProtection.ProtectedFolders.Where(f => f.ControlledFolderAccess).Select(f => f.Path.TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (protectedFolders.Count == 0)
        {
            return RegistryPlan.NotConfigured();
        }

        if (defender.InactiveReason() is { } reason)
        {
            return new RegistryPlan(ControlState.NotSupportedOnEdition, reason, []);
        }

        // 1 = Block. Windows' own folders (Documents, Pictures, Desktop...) are always protected as well.
        var values = new List<PolicyValue> { new(Key, "EnableControlledFolderAccess", 1) };
        values.AddRange(protectedFolders.Select(f => new PolicyValue($@"{Key}\ProtectedFolders", f, "0")));
        return new RegistryPlan(ControlState.Enforced,
            string.Create(CultureInfo.InvariantCulture, $"Microsoft Defender Controlled Folder Access protects {protectedFolders.Count} folder(s) and the Windows user folders: only trusted programs may change files there."),
            values);
    }

    protected override ControlStatus Review(ControlStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        return status.State == ControlState.Enforced && defender.EffectiveControlledFolderAccess() != 1
            ? status with { State = ControlState.PartiallyEnforced, Details = "The setting is in place but Microsoft Defender does not report it as active yet (it usually takes up to a few minutes)." }
            : status;
    }
}

/// <summary>BitLocker protection state of the computer's fixed drives.</summary>
public interface IDiskEncryptionStatus
{
    /// <summary>Null when BitLocker information is available; otherwise why not.</summary>
    string? UnavailableReason();

    /// <summary>Each fixed drive and whether BitLocker protection is on.</summary>
    IReadOnlyList<(string Drive, bool Protected)> Drives();
}

/// <summary>Checks and reports disk encryption. BitLocker is not switched on automatically in this version.</summary>
public sealed class DiskEncryptionEnforcer(IDiskEncryptionStatus disks, TimeProvider clock) : IEnforcer
{
    public SecurityControl Control => SecurityControl.DiskEncryption;

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken) => VerifyAsync(policy, cancellationToken);

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        if (!policy.DiskEncryption.RequireBitLocker)
        {
            return Task.FromResult(new ControlStatus(Control, ControlState.NotConfigured, "Not required by the policy.", now));
        }

        if (disks.UnavailableReason() is { } reason)
        {
            return Task.FromResult(new ControlStatus(Control, ControlState.NotSupportedOnEdition, reason, now));
        }

        var drives = disks.Drives();
        var open = drives.Where(d => !d.Protected).Select(d => d.Drive).ToList();
        return Task.FromResult(open.Count == 0 && drives.Count > 0
            ? new ControlStatus(Control, ControlState.Enforced, "All fixed drives are protected by BitLocker: " + string.Join(", ", drives.Select(d => d.Drive)), now)
            : new ControlStatus(Control, ControlState.Failed,
                "NOT encrypted: " + string.Join(", ", open) + ". Turn on BitLocker on this computer (Control Panel > BitLocker Drive Encryption) and keep the recovery key safe; this system does not switch it on automatically.", now));
    }
}

public sealed class InMemoryAuditPolicy : IAuditPolicy
{
    public Dictionary<Guid, int> Settings { get; } = [];

    public int Query(Guid subcategory) => Settings.GetValueOrDefault(subcategory);

    public void Change(Guid subcategory, bool success, bool failure) => Settings[subcategory] = (success ? 1 : 0) | (failure ? 2 : 0);
}

public sealed class InMemoryFolderAudit : IFolderAudit
{
    public HashSet<string> Folders { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> Audited { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool Exists(string folder) => Folders.Contains(folder);

    public bool HasRule(string folder) => Audited.Contains(folder);

    public void AddRule(string folder) => Audited.Add(folder);

    public void RemoveRule(string folder) => Audited.Remove(folder);
}
