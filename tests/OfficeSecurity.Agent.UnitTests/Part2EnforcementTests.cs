using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

public sealed class Part2EnforcementTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly RecordingEvents _events = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 9, 28, 9, 0, 0, TimeSpan.Zero));

    public void Dispose() => _dir.Dispose();

    private SecurityPolicyDocument Policy(Func<PolicySettings, PolicySettings> change) =>
        change(new PolicySettings()).ToDocument(Guid.NewGuid(), 1, _clock.GetUtcNow());

    // ---------------------------------------------------------------- Application Control

    [Fact]
    public async Task App_control_is_deployed_once_verified_and_removed_when_switched_off()
    {
        var platform = new InMemoryAppControl();
        var enforcer = new AppControlEnforcer(platform, _dir.Path, _events, _clock);
        var audit = Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Audit } });

        var status = await enforcer.ApplyAsync(audit, default);
        Assert.Equal(ControlState.AuditOnly, status.State);
        var (build, active) = Assert.Single(platform.Policies.Values);
        Assert.True(active);
        Assert.True(build.AuditOnly);
        Assert.Equal(AppControlEnforcer.AdministratorFolders, build.AllowedFolders);

        await enforcer.ApplyAsync(audit, default);
        Assert.Equal(1, platform.Deployments); // unchanged settings: not deployed again

        var enforce = Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Enforce, AllowedFolders = [@"D:\CompanyApps\*"] } });
        Assert.Equal(ControlState.Enforced, (await enforcer.ApplyAsync(enforce, default)).State);
        Assert.Equal(2, platform.Deployments);
        var updated = Assert.Single(platform.Policies.Values).Build;
        Assert.False(updated.AuditOnly);
        Assert.Contains(@"D:\CompanyApps\*", updated.AllowedFolders);
        Assert.True(Version.Parse(updated.Version) > Version.Parse(build.Version));

        Assert.Equal(ControlState.NotConfigured, (await enforcer.ApplyAsync(Policy(s => s), default)).State);
        Assert.Empty(platform.Policies);
        Assert.Empty(_events.Raised);
    }

    [Fact]
    public async Task Removed_app_control_policy_is_restored_with_a_critical_event()
    {
        var platform = new InMemoryAppControl();
        var enforcer = new AppControlEnforcer(platform, _dir.Path, _events, _clock);
        var enforce = Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Enforce } });
        await enforcer.ApplyAsync(enforce, default);

        platform.Policies.Clear(); // e.g. "CiTool --remove-policy" by a local administrator
        Assert.Equal(ControlState.Failed, (await enforcer.VerifyAsync(enforce, default)).State);

        Assert.Equal(ControlState.Enforced, (await enforcer.ApplyAsync(enforce, default)).State);
        Assert.Single(platform.Policies);
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, Assert.Single(_events.Raised).Type);
    }

    [Fact]
    public async Task App_control_reports_unsupported_windows_versions_without_deploying()
    {
        var platform = new InMemoryAppControl { Unsupported = "Needs Windows 11 22H2" };
        var enforcer = new AppControlEnforcer(platform, _dir.Path, _events, _clock);

        var status = await enforcer.ApplyAsync(Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Enforce } }), default);

        Assert.Equal(ControlState.NotSupportedOnEdition, status.State);
        Assert.Equal(0, platform.Deployments);
    }

    [Fact]
    public async Task Uninstall_removes_the_app_control_policy()
    {
        var platform = new InMemoryAppControl();
        await new AppControlEnforcer(platform, _dir.Path, _events, _clock).ApplyAsync(Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Audit } }), default);

        Assert.True(AppControlEnforcer.RemoveAll(platform, _dir.Path));
        Assert.Empty(platform.Policies);
        Assert.False(AppControlEnforcer.RemoveAll(platform, _dir.Path));
    }

    // ---------------------------------------------------------------- audit settings

    [Fact]
    public async Task Sign_in_auditing_is_switched_on_restored_and_the_previous_setting_put_back()
    {
        var audit = new InMemoryAuditPolicy();
        audit.Settings[AuditSubcategories.Logon] = 1; // Windows default: successes only
        var store = new InMemoryManagedSettingsStore();
        var enforcer = new SignInAuditEnforcer(new AuditPolicyEngine(audit, store), _events, _clock);
        var on = Policy(s => s with { SignInAudit = new() { RecordWindowsSignIns = true } });

        Assert.Equal(ControlState.Enforced, (await enforcer.ApplyAsync(on, default)).State);
        Assert.Equal(3, audit.Settings[AuditSubcategories.Logon]);
        Assert.Equal(3, audit.Settings[AuditSubcategories.Logoff]);

        audit.Change(AuditSubcategories.Logon, false, false); // someone switches it off
        await enforcer.ApplyAsync(on, default);
        Assert.Equal(3, audit.Settings[AuditSubcategories.Logon]);
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, Assert.Single(_events.Raised).Type);

        Assert.Equal(ControlState.NotConfigured, (await enforcer.ApplyAsync(Policy(s => s), default)).State);
        Assert.Equal(1, audit.Settings[AuditSubcategories.Logon]); // back to what it was
        Assert.Equal(0, audit.Settings[AuditSubcategories.Logoff]);
    }

    [Fact]
    public async Task File_access_records_audit_each_existing_folder_and_report_missing_ones()
    {
        var audit = new InMemoryAuditPolicy();
        var folders = new InMemoryFolderAudit();
        folders.Folders.Add(@"D:\Company");
        var store = new InMemoryManagedSettingsStore();
        var enforcer = new FileAccessAuditEnforcer(new AuditPolicyEngine(audit, store), folders, store, _events, _clock);
        var policy = Policy(s => s with
        {
            FileProtection = new() { ProtectedFolders = [new(@"D:\Company\", true, false), new(@"E:\Missing", true, false), new(@"D:\NotAudited", false, true)] },
        });

        var status = await enforcer.ApplyAsync(policy, default);

        Assert.Equal(ControlState.PartiallyEnforced, status.State);
        Assert.Contains(@"E:\Missing", status.Details, StringComparison.Ordinal);
        Assert.Equal(3, audit.Settings[AuditSubcategories.FileSystem]);
        Assert.Equal([@"D:\Company"], folders.Audited);

        folders.Audited.Clear();
        await enforcer.ApplyAsync(policy, default);
        Assert.Contains(@"D:\Company", folders.Audited);
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, Assert.Single(_events.Raised).Type);

        await enforcer.ApplyAsync(Policy(s => s), default);
        Assert.Empty(folders.Audited);
        Assert.Equal(0, audit.Settings[AuditSubcategories.FileSystem]);
    }

    [Fact]
    public async Task Uninstall_puts_back_audit_settings_and_removes_folder_entries()
    {
        var audit = new InMemoryAuditPolicy();
        var folders = new InMemoryFolderAudit();
        folders.Folders.Add(@"D:\Company");
        var store = new InMemoryManagedSettingsStore();
        var engine = new AuditPolicyEngine(audit, store);
        await new FileAccessAuditEnforcer(engine, folders, store, _events, _clock)
            .ApplyAsync(Policy(s => s with { FileProtection = new() { ProtectedFolders = [new(@"D:\Company", true, false)] } }), default);
        await new SignInAuditEnforcer(engine, _events, _clock).ApplyAsync(Policy(s => s with { SignInAudit = new() { RecordWindowsSignIns = true } }), default);

        Assert.Equal(1, FileAccessAuditEnforcer.RemoveAll(folders, store));
        Assert.Equal(3, engine.RemoveAll());
        Assert.Empty(folders.Audited);
        Assert.All(audit.Settings.Values, v => Assert.Equal(0, v));
    }

    // ---------------------------------------------------------------- ransomware protection, BitLocker

    private sealed class FakeDefender : IDefenderStatus
    {
        public string? Inactive { get; set; }

        public int? Effective { get; set; } = 1;

        public string? InactiveReason() => Inactive;

        public int? EffectiveControlledFolderAccess() => Effective;
    }

    [Fact]
    public async Task Ransomware_protection_writes_the_defender_policy_and_checks_defender_applied_it()
    {
        var registry = new InMemoryPolicyRegistry();
        var defender = new FakeDefender { Effective = 0 };
        var enforcer = new ControlledFolderAccessEnforcer(new RegistryPolicyEngine(registry, new InMemoryManagedSettingsStore()), defender, _events, _clock);
        var policy = Policy(s => s with { FileProtection = new() { ProtectedFolders = [new(@"D:\Company", false, true)] } });

        Assert.Equal(ControlState.PartiallyEnforced, (await enforcer.ApplyAsync(policy, default)).State); // Defender has not picked it up yet
        Assert.Equal(1, registry.Read(ControlledFolderAccessEnforcer.Key, "EnableControlledFolderAccess"));
        Assert.Equal("0", registry.Read($@"{ControlledFolderAccessEnforcer.Key}\ProtectedFolders", @"D:\Company"));

        defender.Effective = 1;
        Assert.Equal(ControlState.Enforced, (await enforcer.VerifyAsync(policy, default)).State);
    }

    [Fact]
    public async Task Ransomware_protection_is_not_supported_without_defender()
    {
        var registry = new InMemoryPolicyRegistry();
        var enforcer = new ControlledFolderAccessEnforcer(new RegistryPolicyEngine(registry, new InMemoryManagedSettingsStore()),
            new FakeDefender { Inactive = "Another antivirus is active." }, _events, _clock);

        var status = await enforcer.ApplyAsync(Policy(s => s with { FileProtection = new() { ProtectedFolders = [new(@"D:\Company", false, true)] } }), default);

        Assert.Equal(ControlState.NotSupportedOnEdition, status.State);
        Assert.Empty(registry.Values);
    }

    private sealed class FakeDisks(params (string, bool)[] drives) : IDiskEncryptionStatus
    {
        public string? Unavailable { get; init; }

        public string? UnavailableReason() => Unavailable;

        public IReadOnlyList<(string Drive, bool Protected)> Drives() => drives;
    }

    [Fact]
    public async Task Disk_encryption_requirement_is_reported_per_drive()
    {
        var required = Policy(s => s with { DiskEncryption = new() { RequireBitLocker = true } });

        Assert.Equal(ControlState.Enforced, (await new DiskEncryptionEnforcer(new FakeDisks(("C:", true), ("D:", true)), _clock).ApplyAsync(required, default)).State);
        var open = await new DiskEncryptionEnforcer(new FakeDisks(("C:", true), ("D:", false)), _clock).ApplyAsync(required, default);
        Assert.Equal(ControlState.Failed, open.State);
        Assert.StartsWith("NOT encrypted: D:", open.Details, StringComparison.Ordinal);
        Assert.Equal(ControlState.NotSupportedOnEdition, (await new DiskEncryptionEnforcer(new FakeDisks() { Unavailable = "Home edition" }, _clock).ApplyAsync(required, default)).State);
        Assert.Equal(ControlState.NotConfigured, (await new DiskEncryptionEnforcer(new FakeDisks(("C:", false)), _clock).ApplyAsync(Policy(s => s), default)).State);
    }
}

public sealed class WindowsEventForwarderTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);
    private readonly FakeEventSource _source = new();
    private readonly PendingEventStore _events;

    public WindowsEventForwarderTests()
    {
        _events = new PendingEventStore(new AgentPaths(_dir.Path), _clock);
    }

    public void Dispose() => _dir.Dispose();

    private sealed class FakeEventSource : IWindowsEventSource
    {
        public List<WindowsEventRecord> Records { get; } = [];

        public long? LatestRecordId(string channel) => Records.Where(r => r.Channel == channel).Select(r => (long?)r.RecordId).Max();

        public IReadOnlyList<WindowsEventRecord> ReadAfter(string channel, IReadOnlyCollection<int> eventIds, long afterRecordId, int max) =>
            [.. Records.Where(r => r.Channel == channel && eventIds.Contains(r.EventId) && r.RecordId > afterRecordId).OrderBy(r => r.RecordId).Take(max)];

        public void Add(string channel, int id, params (string Name, string Value)[] data) =>
            Records.Add(new WindowsEventRecord(channel, id, Records.Count + 1, DateTimeOffset.UtcNow, data.ToDictionary(d => d.Name, d => d.Value)));
    }

    private static readonly SecurityPolicyDocument Everything = new PolicySettings
    {
        ApplicationControl = new() { Mode = EnforcementMode.Enforce },
        SignInAudit = new() { RecordWindowsSignIns = true },
        FileProtection = new() { ProtectedFolders = [new(@"D:\Company", true, true)] },
    }.ToDocument(Guid.NewGuid(), 1, DateTimeOffset.UtcNow);

    private List<AgentEvent> Forward(SecurityPolicyDocument policy)
    {
        new WindowsEventForwarder(_source, _events, _dir.Path, _clock).Collect(policy);
        var sent = _events.PeekPending(1000).ToList();
        _events.MarkUploaded(sent.Select(e => e.EventId));
        return sent;
    }

    [Fact]
    public void History_before_the_feature_was_switched_on_is_not_reported()
    {
        _source.Add(WindowsEventForwarder.SecurityLog, 4625, ("TargetUserName", "old"), ("LogonType", "2"));

        Assert.Empty(Forward(Everything));
        _source.Add(WindowsEventForwarder.SecurityLog, 4625, ("TargetUserName", "new"), ("TargetDomainName", "PC1"), ("LogonType", "2"), ("SubStatus", "0xC000006A"));
        var e = Assert.Single(Forward(Everything));
        Assert.Equal(SecurityEventType.FailedLogin, e.Type);
        Assert.Equal(@"Failed Windows sign-in for PC1\new (at the computer): wrong password.", e.Details);
    }

    [Fact]
    public void Events_are_mapped_filtered_and_deduplicated()
    {
        var forwarder = new WindowsEventForwarder(_source, _events, _dir.Path, _clock);
        forwarder.Collect(Everything); // bookmarks at "now"
        const string Sid = "S-1-5-21-1-2-3-1001";

        _source.Add(WindowsEventForwarder.CodeIntegrityLog, 3077, ("File Name", @"C:\Users\anna\Downloads\game.exe"), ("Process Name", @"C:\Windows\explorer.exe"), ("PolicyName", "Office Security System"));
        _source.Add(WindowsEventForwarder.CodeIntegrityLog, 3077, ("File Name", @"C:\drivers\old.sys"), ("PolicyName", "Microsoft Windows Driver Policy")); // not ours
        _source.Add(WindowsEventForwarder.SecurityLog, 4624, ("TargetUserSid", Sid), ("TargetUserName", "anna"), ("TargetDomainName", "PC1"), ("LogonType", "2"));
        _source.Add(WindowsEventForwarder.SecurityLog, 4624, ("TargetUserSid", Sid), ("TargetUserName", "anna"), ("TargetDomainName", "PC1"), ("LogonType", "2")); // same sign-in, split token
        _source.Add(WindowsEventForwarder.SecurityLog, 4624, ("TargetUserSid", "S-1-5-18"), ("TargetUserName", "SYSTEM"), ("LogonType", "5")); // service
        _source.Add(WindowsEventForwarder.SecurityLog, 4663, ("SubjectUserSid", Sid), ("SubjectUserName", "anna"), ("SubjectDomainName", "PC1"),
            ("ObjectName", @"D:\Company\salaries.xlsx"), ("AccessMask", "0x1"), ("ProcessName", @"C:\Program Files\Microsoft Office\EXCEL.EXE"));
        _source.Add(WindowsEventForwarder.SecurityLog, 4663, ("SubjectUserSid", Sid), ("SubjectUserName", "anna"), ("ObjectName", @"D:\Other\x.txt"), ("AccessMask", "0x1"));
        _source.Add(WindowsEventForwarder.SecurityLog, 4663, ("SubjectUserSid", Sid), ("SubjectUserName", "anna"), ("SubjectDomainName", "PC1"),
            ("ObjectName", @"D:\Company\old.docx"), ("AccessMask", "0x10000"), ("ProcessName", @"C:\Windows\explorer.exe"));
        _source.Add(WindowsEventForwarder.SecurityLog, 4647, ("TargetUserSid", Sid), ("TargetUserName", "anna"), ("TargetDomainName", "PC1"));
        _source.Add(WindowsEventForwarder.DefenderLog, 1123, ("Process Name", @"C:\Users\anna\AppData\x.exe"), ("Path", @"D:\Company\a.docx"), ("User", @"PC1\anna"));

        forwarder.Collect(Everything);
        var sent = _events.PeekPending(1000);

        Assert.Equal(
        [
            SecurityEventType.UnauthorizedApplicationBlocked, SecurityEventType.SuccessfulLogin, SecurityEventType.ProtectedFileAccess,
            SecurityEventType.ProtectedFileAccess, SecurityEventType.Logout, SecurityEventType.PolicyViolation,
        ], sent.Select(e => e.Type));
        Assert.Contains("game.exe", sent[0].Details, StringComparison.Ordinal);
        Assert.Equal(EventSeverities.Warning, sent[0].Severity);
        Assert.Equal(@"PC1\anna signed in to Windows (at the computer).", sent[1].Details);
        Assert.Equal(@"PC1\anna opened D:\Company\salaries.xlsx (program: C:\Program Files\Microsoft Office\EXCEL.EXE).", sent[2].Details);
        Assert.StartsWith(@"PC1\anna deleted D:\Company\old.docx", sent[3].Details, StringComparison.Ordinal);
        Assert.Contains("Ransomware protection blocked", sent[5].Details, StringComparison.Ordinal);

        // The same file opened again within 10 minutes is reported once.
        _source.Add(WindowsEventForwarder.SecurityLog, 4663, ("SubjectUserSid", Sid), ("SubjectUserName", "anna"), ("ObjectName", @"D:\Company\salaries.xlsx"), ("AccessMask", "0x1"));
        forwarder.Collect(Everything);
        Assert.Equal(sent.Count, _events.PeekPending(1000).Count);
    }

    [Fact]
    public void Audit_mode_blocks_are_reported_as_would_be_blocked()
    {
        var audit = new PolicySettings { ApplicationControl = new() { Mode = EnforcementMode.Audit } }.ToDocument(Guid.NewGuid(), 1, DateTimeOffset.UtcNow);
        Forward(audit);
        _source.Add(WindowsEventForwarder.CodeIntegrityLog, 3076, ("File Name", @"C:\Users\anna\Desktop\tool.exe"), ("Process Name", "explorer.exe"), ("PolicyName", "Office Security System"));

        var e = Assert.Single(Forward(audit));
        Assert.StartsWith("Audit mode — would be blocked", e.Details, StringComparison.Ordinal);
        Assert.Equal(EventSeverities.Information, e.Severity);
    }

    [Fact]
    public void Nothing_is_read_for_features_that_are_off()
    {
        _source.Add(WindowsEventForwarder.SecurityLog, 4625, ("TargetUserName", "x"), ("LogonType", "2"));
        Assert.Empty(Forward(new PolicySettings().ToDocument(Guid.NewGuid(), 1, DateTimeOffset.UtcNow)));
        Assert.False(File.Exists(Path.Combine(_dir.Path, "event-bookmarks.json")) && File.ReadAllText(Path.Combine(_dir.Path, "event-bookmarks.json")).Contains("Security", StringComparison.Ordinal));
    }
}
