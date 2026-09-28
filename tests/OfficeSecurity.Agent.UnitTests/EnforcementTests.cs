using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

public sealed class RecordingEvents : IEnforcementEvents
{
    public List<(SecurityEventType Type, string Severity, string Details)> Raised { get; } = [];

    public void Raise(SecurityEventType type, string severity, string details) => Raised.Add((type, severity, details));
}

/// <summary>A registry where writes to one key silently do not stick (e.g. blocked by another product).</summary>
public sealed class StubbornRegistry(string ignoredKey) : IPolicyRegistry
{
    public InMemoryPolicyRegistry Inner { get; } = new();

    public object? Read(string key, string name) => Inner.Read(key, name);

    public void Write(PolicyValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.Key.Equals(ignoredKey, StringComparison.OrdinalIgnoreCase))
        {
            Inner.Write(value);
        }
    }

    public void Delete(string key, string name) => Inner.Delete(key, name);
}

public sealed class RegistryPolicyEngineTests
{
    private static readonly PolicyValue A = new(@"SOFTWARE\Policies\Test", "A", 1);
    private static readonly PolicyValue B = new(@"SOFTWARE\Policies\Test", "B", "text");

    private readonly InMemoryPolicyRegistry _registry = new();
    private readonly InMemoryManagedSettingsStore _store = new();

    private RegistryPolicyEngine Engine => new(_registry, _store);

    [Fact]
    public void Writes_values_and_verifies_them()
    {
        var result = Engine.Apply(SecurityControl.RemovableStorage, [A, B]);

        Assert.True(result.IsVerified);
        Assert.Equal(2, result.Written.Count);
        Assert.Equal(1, _registry.Read(A.Key, A.Name));
        Assert.Equal("text", _registry.Read(B.Key, B.Name));
        Assert.Empty(Engine.Apply(SecurityControl.RemovableStorage, [A, B]).Written); // idempotent
    }

    [Fact]
    public void A_value_changed_by_someone_else_is_restored_and_reported()
    {
        Engine.Apply(SecurityControl.RemovableStorage, [A, B]);
        _registry.Delete(A.Key, A.Name);
        _registry.Write(B with { Data = "changed" });

        var result = Engine.Apply(SecurityControl.RemovableStorage, [A, B]);

        Assert.Equal(2, result.Restored.Count);
        Assert.Equal(1, _registry.Read(A.Key, A.Name));
        Assert.Equal("text", _registry.Read(B.Key, B.Name));
    }

    [Fact]
    public void A_pre_existing_foreign_value_is_replaced_and_reported_but_not_as_tampering()
    {
        _registry.Write(A with { Data = 0 });

        var result = Engine.Apply(SecurityControl.RemovableStorage, [A]);

        Assert.Empty(result.Restored);
        Assert.Single(result.ReplacedForeign);
        Assert.Equal(1, _registry.Read(A.Key, A.Name));
    }

    [Fact]
    public void Only_values_it_wrote_are_removed_when_no_longer_wanted()
    {
        Engine.Apply(SecurityControl.RemovableStorage, [A, B]);
        _registry.Write(B with { Data = "an administrator's own value" });

        var result = Engine.Apply(SecurityControl.RemovableStorage, []);

        Assert.Single(result.Removed);
        Assert.Null(_registry.Read(A.Key, A.Name));
        Assert.Equal("an administrator's own value", _registry.Read(B.Key, B.Name));
        Assert.Empty(_store.Load(SecurityControl.RemovableStorage));
    }

    [Fact]
    public void Remove_all_removes_every_value_it_wrote_for_every_control()
    {
        var other = new PolicyValue(@"SOFTWARE\Policies\Other", "X", 5);
        Engine.Apply(SecurityControl.RemovableStorage, [A]);
        Engine.Apply(SecurityControl.BrowserRestrictions, [other]);
        _registry.Write(new PolicyValue(@"SOFTWARE\Policies\Unrelated", "Y", 1));

        Assert.Equal(2, Engine.RemoveAll());
        Assert.Single(_registry.Values);
        Assert.Empty(_store.LoadAll());
    }

    [Fact]
    public void A_value_that_does_not_stick_is_reported_as_not_verified()
    {
        var registry = new StubbornRegistry(A.Key);
        var result = new RegistryPolicyEngine(registry, _store).Apply(SecurityControl.RemovableStorage, [A]);

        Assert.False(result.IsVerified);
        Assert.Equal(A, Assert.Single(result.Mismatched));
    }

    [Fact]
    public void File_store_keeps_what_was_written_across_restarts()
    {
        using var dir = new TempDirectory();
        new FileManagedSettingsStore(dir.Path).Save(SecurityControl.BrowserRestrictions, [A, B]);

        var loaded = new FileManagedSettingsStore(dir.Path).Load(SecurityControl.BrowserRestrictions);

        Assert.Equal([A, B], loaded);
        Assert.Empty(new FileManagedSettingsStore(dir.Path, FileManagedSettingsStore.FirewallFile).LoadAll());
    }
}

public sealed class SecurityControlTests
{
    private readonly InMemoryPolicyRegistry _registry = new();
    private readonly InMemoryManagedSettingsStore _store = new();
    private readonly RecordingEvents _events = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 9, 28, 9, 0, 0, TimeSpan.Zero));

    private RegistryPolicyEngine Engine => new(_registry, _store);

    private SecurityPolicyDocument Policy(Func<PolicySettings, PolicySettings> change, params PolicyExemption[] exemptions) =>
        change(new PolicySettings()).ToDocument(Guid.NewGuid(), 1, _clock.GetUtcNow(), exemptions);

    private object? Value(string key, string name) => _registry.Read(key, name);

    [Fact]
    public async Task Usb_blocking_off_audit_and_enforce()
    {
        var usb = new RemovableStorageEnforcer(Engine, _events, _clock);
        var disks = $@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.RemovableDisks}";
        var dvd = $@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.CdAndDvd}";

        Assert.Equal(ControlState.NotConfigured, (await usb.ApplyAsync(Policy(s => s), default)).State);
        Assert.Empty(_registry.Values);

        var audit = await usb.ApplyAsync(Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Audit } }), default);
        Assert.Equal(ControlState.AuditOnly, audit.State);
        Assert.Empty(_registry.Values);

        var enforced = await usb.ApplyAsync(Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce, BlockOpticalDrives = true } }), default);
        Assert.Equal(ControlState.Enforced, enforced.State);
        Assert.Equal(1, Value(disks, "Deny_Read"));
        Assert.Equal(1, Value(disks, "Deny_Write"));
        Assert.Equal(1, Value(disks, "Deny_Execute"));
        Assert.Equal(1, Value(dvd, "Deny_Read"));

        // CD/DVD allowed again: only those values are removed.
        await usb.ApplyAsync(Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce, BlockOpticalDrives = false } }), default);
        Assert.Null(Value(dvd, "Deny_Read"));
        Assert.Equal(1, Value(disks, "Deny_Read"));

        // Off: everything the agent set is removed.
        await usb.ApplyAsync(Policy(s => s), default);
        Assert.Empty(_registry.Values);
        Assert.Empty(_events.Raised);
    }

    [Fact]
    public async Task Removed_usb_block_is_restored_with_a_critical_event()
    {
        var usb = new RemovableStorageEnforcer(Engine, _events, _clock);
        var policy = Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce } });
        await usb.ApplyAsync(policy, default);
        var disks = $@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.RemovableDisks}";
        _registry.Delete(disks, "Deny_Write");

        Assert.Equal(ControlState.Failed, (await usb.VerifyAsync(policy, default)).State); // Verify never changes anything
        Assert.Null(Value(disks, "Deny_Write"));

        var status = await usb.ApplyAsync(policy, default);

        Assert.Equal(ControlState.Enforced, status.State);
        Assert.Equal(1, Value(disks, "Deny_Write"));
        var alert = Assert.Single(_events.Raised);
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, alert.Type);
        Assert.Equal(EventSeverities.Critical, alert.Severity);
    }

    [Fact]
    public async Task Temporary_exception_lifts_the_block_until_it_expires()
    {
        var usb = new RemovableStorageEnforcer(Engine, _events, _clock);
        var exemption = new PolicyExemption(Guid.NewGuid(), SecurityControl.RemovableStorage, "Copy scanner files", _clock.GetUtcNow(), _clock.GetUtcNow().AddHours(2));
        var policy = Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce } }, exemption);

        var lifted = await usb.ApplyAsync(policy, default);
        Assert.Equal(ControlState.TemporarilyAllowed, lifted.State);
        Assert.Contains("Copy scanner files", lifted.Details, StringComparison.Ordinal);
        Assert.Empty(_registry.Values);

        _clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(ControlState.Enforced, (await usb.ApplyAsync(policy, default)).State);
        Assert.NotEmpty(_registry.Values);
        Assert.Empty(_events.Raised); // Restoring after an exception is not tampering.
    }

    [Fact]
    public async Task Exception_for_another_control_does_not_lift_usb_blocking()
    {
        var usb = new RemovableStorageEnforcer(Engine, _events, _clock);
        var exemption = new PolicyExemption(Guid.NewGuid(), SecurityControl.BrowserRestrictions, "x", _clock.GetUtcNow(), _clock.GetUtcNow().AddHours(1));

        var status = await usb.ApplyAsync(Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce } }, exemption), default);

        Assert.Equal(ControlState.Enforced, status.State);
    }

    [Fact]
    public async Task Phones_are_blocked_through_both_portable_device_classes()
    {
        var phones = new MobileDeviceTransferEnforcer(Engine, _events, _clock);

        Assert.Equal(ControlState.NotConfigured, (await phones.ApplyAsync(Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce, BlockPortableDevices = false } }), default)).State);
        var status = await phones.ApplyAsync(Policy(s => s with { RemovableStorage = new() { Mode = EnforcementMode.Enforce, BlockPortableDevices = true } }), default);

        Assert.Equal(ControlState.Enforced, status.State);
        foreach (var wpd in RemovableStoragePolicy.WpdDevices)
        {
            Assert.Equal(1, Value($@"{RemovableStoragePolicy.Root}\{wpd}", "Deny_Read"));
            Assert.Equal(1, Value($@"{RemovableStoragePolicy.Root}\{wpd}", "Deny_Write"));
        }
    }

    [Fact]
    public async Task Staff_installation_block_is_reported_as_partial_with_what_is_not_covered()
    {
        var installs = new SoftwareInstallationEnforcer(Engine, _events, _clock);

        var status = await installs.ApplyAsync(Policy(s => s with { SoftwareInstallation = new() { BlockStaffInstalls = true } }), default);

        Assert.Equal(ControlState.PartiallyEnforced, status.State);
        Assert.Contains("NOT blocked yet", status.Details, StringComparison.Ordinal);
        Assert.Equal(1, Value(SoftwareInstallationEnforcer.InstallerKey, "DisableMSI"));
        Assert.Equal(1, Value(SoftwareInstallationEnforcer.AppxKey, "BlockNonAdminUserInstall"));
    }

    [Fact]
    public async Task Website_lists_and_private_browsing_are_written_for_edge_chrome_and_firefox()
    {
        var browser = new BrowserEnforcer(Engine, _events, _clock);
        var policy = Policy(s => s with { Browser = new() { BlockedUrls = ["facebook.com", "wetransfer.com", "*"], AllowedUrls = ["office.example"], DisablePrivateBrowsing = true } });

        var status = await browser.ApplyAsync(policy, default);

        Assert.Equal(ControlState.Enforced, status.State);
        foreach (var key in new[] { BrowserEnforcer.EdgeKey, BrowserEnforcer.ChromeKey })
        {
            Assert.Equal("facebook.com", Value($@"{key}\URLBlocklist", "1"));
            Assert.Equal("*", Value($@"{key}\URLBlocklist", "3"));
            Assert.Equal("office.example", Value($@"{key}\URLAllowlist", "1"));
        }

        Assert.Equal(1, Value(BrowserEnforcer.EdgeKey, "InPrivateModeAvailability"));
        Assert.Equal(1, Value(BrowserEnforcer.ChromeKey, "IncognitoModeAvailability"));
        Assert.Equal(1, Value(BrowserEnforcer.FirefoxKey, "DisablePrivateBrowsing"));
        Assert.Equal("*://*.facebook.com/*", Value($@"{BrowserEnforcer.FirefoxKey}\WebsiteFilter\Block", "1"));
        Assert.Equal("<all_urls>", Value($@"{BrowserEnforcer.FirefoxKey}\WebsiteFilter\Block", "3"));

        // A shorter list removes the entries that are no longer wanted.
        await browser.ApplyAsync(Policy(s => s with { Browser = new() { BlockedUrls = ["facebook.com"] } }), default);
        Assert.Null(Value($@"{BrowserEnforcer.EdgeKey}\URLBlocklist", "2"));
        Assert.Null(Value(BrowserEnforcer.EdgeKey, "InPrivateModeAvailability"));
        Assert.Equal("facebook.com", Value($@"{BrowserEnforcer.EdgeKey}\URLBlocklist", "1"));
    }

    [Theory]
    [InlineData("example.com", "*://*.example.com/*")]
    [InlineData("example.com/files", "*://*.example.com/files*")]
    [InlineData("https://drive.example.com", "https://drive.example.com/*")]
    [InlineData("https://drive.example.com/*", "https://drive.example.com/*")]
    [InlineData("*", "<all_urls>")]
    public void Firefox_patterns(string entry, string expected) =>
        Assert.Equal(expected, BrowserEnforcer.ToFirefoxPattern(entry));

    [Fact]
    public async Task Firewall_rules_are_created_restored_and_removed()
    {
        var firewall = new InMemoryFirewall();
        var enforcer = new FirewallEnforcer(firewall, _store, _events, _clock);
        const string Dropbox = @"C:\Program Files\Dropbox\Dropbox.exe";
        const string Torrent = @"C:\Users\Public\torrent.exe";
        var policy = Policy(s => s with { Network = new() { BlockedApplicationPaths = [Dropbox, Torrent] } });

        var status = await enforcer.ApplyAsync(policy, default);
        Assert.Equal(ControlState.Enforced, status.State);
        Assert.Equal(2, firewall.Rules.Count);
        Assert.All(firewall.Rules.Values, r => Assert.True(r.IsOutboundBlock));

        // Someone deletes one rule and disables the other: both are put back.
        firewall.Rules.Remove(FirewallEnforcer.RuleName(Dropbox));
        var torrentRule = FirewallEnforcer.RuleName(Torrent);
        firewall.Rules[torrentRule] = firewall.Rules[torrentRule] with { Enabled = false };
        await enforcer.ApplyAsync(policy, default);
        Assert.Equal(2, firewall.Rules.Count);
        Assert.True(firewall.Rules[torrentRule].Enabled);
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, Assert.Single(_events.Raised).Type);

        // Firewall switched off on one profile: reported, never switched on by the agent.
        firewall.Disabled = FirewallProfiles.Public;
        var partial = await enforcer.ApplyAsync(policy, default);
        Assert.Equal(ControlState.PartiallyEnforced, partial.State);
        Assert.Contains("turned off for the Public", partial.Details, StringComparison.Ordinal);
        Assert.Equal(FirewallProfiles.Public, firewall.Disabled);

        // Removed from the policy: the rule goes; unrelated rules stay.
        firewall.AddOutboundBlock("Someone else's rule", @"C:\x.exe", "other");
        await enforcer.ApplyAsync(Policy(s => s with { Network = new() { BlockedApplicationPaths = [Dropbox] } }), default);
        Assert.Equal([FirewallEnforcer.RuleName(Dropbox), "Someone else's rule"], firewall.Rules.Keys.Order());

        Assert.Equal(1, FirewallEnforcer.RemoveAll(firewall, _store));
        Assert.Equal("Someone else's rule", Assert.Single(firewall.Rules.Keys));
    }

    [Fact]
    public async Task Wifi_restriction_without_wifi_support_is_reported_as_not_in_effect()
    {
        var enforcer = new FirewallEnforcer(new InMemoryFirewall(), _store, _events, _clock);

        var status = await enforcer.ApplyAsync(Policy(s => s with { Network = new() { AllowedWifiNetworks = ["Office"] } }), default);

        Assert.Equal(ControlState.Failed, status.State);
        Assert.Contains("Not in effect", status.Details, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_setting_that_does_not_stick_makes_the_control_failed_not_enforced()
    {
        var registry = new StubbornRegistry(SoftwareInstallationEnforcer.AppxKey);
        var installs = new SoftwareInstallationEnforcer(new RegistryPolicyEngine(registry, _store), _events, _clock);

        var status = await installs.ApplyAsync(Policy(s => s with { SoftwareInstallation = new() { BlockStaffInstalls = true } }), default);

        Assert.Equal(ControlState.Failed, status.State);
        Assert.Contains("BlockNonAdminUserInstall", status.Details, StringComparison.Ordinal);
    }
}

public sealed class RuntimeEnforcementTests
{
    private static (AgentHarness Agent, InMemoryPolicyRegistry Registry) Start(FakeAgentServer server)
    {
        var agent = new AgentHarness(server);
        var registry = new InMemoryPolicyRegistry();
        var events = new Core.QueuedEnforcementEvents(agent.Events);
        var engine = new RegistryPolicyEngine(registry, new InMemoryManagedSettingsStore());
        agent.Enforcers.Add(new RemovableStorageEnforcer(engine, events, agent.Clock));
        agent.Enforcers.Add(new MobileDeviceTransferEnforcer(engine, events, agent.Clock));
        agent.Restart();
        return (agent, registry);
    }

    [Fact]
    public async Task Usb_drive_connected_while_blocked_is_reported_as_blocked()
    {
        using var server = new FakeAgentServer { Settings = new PolicySettings { RemovableStorage = new() { Mode = EnforcementMode.Enforce } } };
        var (agent, _) = Start(server);
        using var _agent = agent;

        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.Equal(ControlState.Enforced, agent.Runtime.Controls.Single(c => c.Control == SecurityControl.RemovableStorage).State);

        agent.Inventory.Devices.Add(new ConnectedDevice(@"USBSTOR\DISK&VEN_KINGSTON\123", "Kingston DataTraveler", "DiskDrive", "Kingston"));
        agent.Inventory.Devices.Add(new ConnectedDevice(@"USB\VID_05AC&PID_12A8\ABC", "Apple iPhone", "WPD", "Apple"));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        var blocked = server.Events.Where(e => e.Type == SecurityEventType.RemovableStorageBlocked).ToList();
        Assert.Equal(2, blocked.Count);
        Assert.Contains(blocked, e => e.Details!.Contains("Kingston DataTraveler", StringComparison.Ordinal));
        Assert.Contains(blocked, e => e.Details!.Contains("Apple iPhone", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Audit_mode_reports_what_would_be_blocked()
    {
        using var server = new FakeAgentServer { Settings = new PolicySettings { RemovableStorage = new() { Mode = EnforcementMode.Audit } } };
        var (agent, registry) = Start(server);
        using var _agent = agent;
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        agent.Inventory.Devices.Add(new ConnectedDevice(@"USBSTOR\DISK&VEN_TEST\1", "Test USB Drive", "DiskDrive", "Test"));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Empty(registry.Values);
        var e = Assert.Single(server.Events, x => x.Type == SecurityEventType.UnauthorizedUsbConnection);
        Assert.Contains("would be blocked", e.Details, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_removed_protection_is_restored_at_the_next_check()
    {
        using var server = new FakeAgentServer { Settings = new PolicySettings { RemovableStorage = new() { Mode = EnforcementMode.Enforce } } };
        var (agent, registry) = Start(server);
        using var _agent = agent;
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        var key = $@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.RemovableDisks}";
        Assert.Equal(1, registry.Read(key, "Deny_Read"));

        registry.Delete(key, "Deny_Read");
        agent.Clock.Advance(TimeSpan.FromSeconds(61));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Equal(1, registry.Read(key, "Deny_Read"));
        Assert.Contains(server.Events, x => x.Type == SecurityEventType.PolicyTamperAttempt && x.Severity == EventSeverities.Critical);
    }

    [Fact]
    public async Task Start_and_end_of_a_temporary_exception_are_recorded()
    {
        using var server = new FakeAgentServer { Settings = new PolicySettings { RemovableStorage = new() { Mode = EnforcementMode.Enforce } } };
        var (agent, registry) = Start(server);
        using var _agent = agent;
        var start = agent.Clock.GetUtcNow();
        server.Exemptions = [new PolicyExemption(Guid.NewGuid(), SecurityControl.RemovableStorage, "Scanner files", start.AddMinutes(-1), start.AddMinutes(30))];

        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        var disks = $@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.RemovableDisks}";
        Assert.Equal(ControlState.TemporarilyAllowed, agent.Runtime.Controls.Single(c => c.Control == SecurityControl.RemovableStorage).State);
        Assert.Null(registry.Read(disks, "Deny_Read"));
        Assert.Equal(ControlState.Enforced, agent.Runtime.Controls.Single(c => c.Control == SecurityControl.MobileDeviceTransfer).State); // not covered by the exception

        agent.Clock.Advance(TimeSpan.FromMinutes(31));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Equal(ControlState.Enforced, agent.Runtime.Controls.Single(c => c.Control == SecurityControl.RemovableStorage).State);
        Assert.Equal(1, registry.Read(disks, "Deny_Read"));
        Assert.Contains(server.Events, x => x.Details!.Contains("lifted on this computer", StringComparison.Ordinal));
        Assert.Contains(server.Events, x => x.Details!.Contains("Temporary exception for RemovableStorage ended", StringComparison.Ordinal));
    }
}
