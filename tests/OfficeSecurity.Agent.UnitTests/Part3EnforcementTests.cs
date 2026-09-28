using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

public sealed class Part3EnforcementTests : IDisposable
{
    private const string Disk = @"USBSTOR\DISK&VEN_KINGSTON&PROD_DT&REV_1.00\123456&0";
    private const string Usb = @"USB\VID_0951&PID_1666\123456";

    private readonly TempDirectory _dir = new();
    private readonly RecordingEvents _events = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 9, 28, 9, 0, 0, TimeSpan.Zero));
    private readonly InMemoryPolicyRegistry _registry = new();
    private readonly InMemoryManagedSettingsStore _store = new();

    public void Dispose() => _dir.Dispose();

    private RegistryPolicyEngine Engine => new(_registry, _store);

    private SecurityPolicyDocument Policy(Func<PolicySettings, PolicySettings> change, params PolicyExemption[] exemptions) =>
        change(new PolicySettings()).ToDocument(Guid.NewGuid(), 1, _clock.GetUtcNow(), exemptions);

    private static PolicySettings WithApproved(PolicySettings s, DateTimeOffset? expires = null) => s with
    {
        RemovableStorage = new() { Mode = EnforcementMode.Enforce, ApprovedDevices = [new ApprovedDevice(Disk, "Accounts backup drive", expires, Usb)] },
    };

    // ---------------------------------------------------------------- approved USB drives

    [Fact]
    public async Task Approved_drives_switch_usb_blocking_to_the_device_installation_policy()
    {
        var devices = new InMemoryUsbStorageDevices();
        devices.Nodes.Add(new StorageDeviceNode(Usb, true));
        devices.Nodes.Add(new StorageDeviceNode(@"USB\VID_1234&PID_0001\OLDSTICK", false)); // seen before, unapproved
        var approvedDevices = new ApprovedDevicesEnforcer(Engine, devices, _events, _clock);
        var usb = new RemovableStorageEnforcer(Engine, _events, _clock);
        var policy = Policy(s => WithApproved(s));

        var usbStatus = await usb.ApplyAsync(policy, default);
        var status = await approvedDevices.ApplyAsync(policy, default);

        Assert.Equal(ControlState.Enforced, status.State);
        Assert.Contains("Accounts backup drive", status.Details, StringComparison.Ordinal);
        var disks = $@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.RemovableDisks}";
        Assert.Null(_registry.Read(disks, "Deny_Read"));          // per-device control instead
        Assert.Equal(1, _registry.Read(disks, "Deny_Execute"));    // programs still cannot run from USB drives
        Assert.Contains("approved", usbStatus.Details, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, _registry.Read(ApprovedDevicesEnforcer.Key, "AllowDenyLayered"));
        Assert.Equal(ApprovedDevicesEnforcer.UsbMassStorage, _registry.Read($@"{ApprovedDevicesEnforcer.Key}\DenyDeviceIDs", "1"));
        Assert.Equal(new object[] { Usb, Disk }.Order(), new[] { _registry.Read($@"{ApprovedDevicesEnforcer.Key}\AllowInstanceIDs", "1"), _registry.Read($@"{ApprovedDevicesEnforcer.Key}\AllowInstanceIDs", "2") }.Order());
        Assert.Equal([@"USB\VID_1234&PID_0001\OLDSTICK"], devices.Removed); // the unapproved one is uninstalled
        Assert.Single(devices.Nodes);
        Assert.Equal(SecurityEventType.RemovableStorageBlocked, Assert.Single(_events.Raised).Type);
    }

    [Fact]
    public async Task Expired_approvals_and_exceptions_are_respected()
    {
        var devices = new InMemoryUsbStorageDevices();
        var enforcer = new ApprovedDevicesEnforcer(Engine, devices, _events, _clock);

        var expired = await enforcer.ApplyAsync(Policy(s => WithApproved(s, _clock.GetUtcNow().AddMinutes(-1))), default);
        Assert.Equal(ControlState.NotConfigured, expired.State);
        Assert.Empty(_registry.Values);

        var exemption = new PolicyExemption(Guid.NewGuid(), SecurityControl.RemovableStorage, "x", _clock.GetUtcNow(), _clock.GetUtcNow().AddHours(1));
        Assert.Equal(ControlState.NotConfigured, (await enforcer.ApplyAsync(Policy(s => WithApproved(s), exemption), default)).State);
        Assert.Empty(_registry.Values);

        await enforcer.ApplyAsync(Policy(s => WithApproved(s)), default);
        Assert.NotEmpty(_registry.Values);
        await enforcer.ApplyAsync(Policy(s => s), default); // switched off: every value removed
        Assert.Empty(_registry.Values);
    }

    [Fact]
    public async Task Approved_drive_connection_is_reported_as_approved()
    {
        using var server = new FakeAgentServer { Settings = WithApproved(new PolicySettings()) };
        using var agent = new AgentHarness(server);
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        agent.Inventory.Devices.Add(new ConnectedDevice(Disk, "Kingston DT", "DiskDrive", "Kingston", Usb));
        agent.Inventory.Devices.Add(new ConnectedDevice(@"USBSTOR\DISK&VEN_OTHER\9", "Other stick", "DiskDrive", "Other"));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Contains(server.Events, e => e.Type == SecurityEventType.ApprovedDeviceConnected && e.Details!.Contains("Accounts backup drive", StringComparison.Ordinal));
        Assert.DoesNotContain(server.Events, e => e.Type == SecurityEventType.ApprovedDeviceConnected && e.Details!.Contains("Other stick", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------- Wi-Fi

    [Fact]
    public async Task Wifi_is_restricted_to_the_listed_networks_with_the_safety_rule()
    {
        var wifi = new InMemoryWifi { Connected = "Phone hotspot" };
        var enforcer = new FirewallEnforcer(new InMemoryFirewall(), new InMemoryManagedSettingsStore(), _events, _clock, new WifiRestriction(wifi, _store, _events));
        var policy = Policy(s => s with { Network = new() { AllowedWifiNetworks = ["Office-WiFi"] } });

        // Connected to a network not on the list: nothing is changed.
        var waiting = await enforcer.ApplyAsync(policy, default);
        Assert.Equal(ControlState.Failed, waiting.State);
        Assert.Contains("Phone hotspot", waiting.Details, StringComparison.Ordinal);
        Assert.False(wifi.DenyAllOn);

        wifi.Connected = "Office-WiFi";
        var status = await enforcer.ApplyAsync(policy, default);
        Assert.Equal(ControlState.Enforced, status.State);
        Assert.True(wifi.DenyAllOn);
        Assert.Equal(["Office-WiFi"], wifi.AllowList);

        wifi.DenyAllOn = false; // someone deletes the filter
        await enforcer.ApplyAsync(policy, default);
        Assert.True(wifi.DenyAllOn);
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, Assert.Single(_events.Raised).Type);

        await enforcer.ApplyAsync(Policy(s => s), default); // switched off
        Assert.False(wifi.DenyAllOn);
        Assert.Empty(wifi.AllowList);
    }

    [Fact]
    public async Task Computers_without_wifi_report_nothing_to_restrict()
    {
        var enforcer = new FirewallEnforcer(new InMemoryFirewall(), new InMemoryManagedSettingsStore(), _events, _clock,
            new WifiRestriction(new InMemoryWifi { HasWifi = false }, _store, _events));

        var status = await enforcer.ApplyAsync(Policy(s => s with { Network = new() { AllowedWifiNetworks = ["Office-WiFi"] } }), default);

        Assert.Equal(ControlState.Enforced, status.State);
        Assert.Contains("no Wi-Fi", status.Details, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- Bluetooth

    [Fact]
    public async Task Bluetooth_radio_is_switched_off_kept_off_and_switched_back_on()
    {
        var radios = new InMemoryBluetooth();
        radios.Adapters[@"USB\VID_8087&PID_0026\5&1"] = false;
        var enforcer = new BluetoothEnforcer(radios, _store, _events, _clock);
        var off = Policy(s => s with { Bluetooth = new() { Mode = BluetoothMode.DisableRadio } });

        Assert.Equal(ControlState.Enforced, (await enforcer.ApplyAsync(off, default)).State);
        Assert.True(radios.Adapters.Values.Single());

        radios.Adapters[@"USB\VID_8087&PID_0026\5&1"] = false; // switched on in Device Manager
        await enforcer.ApplyAsync(off, default);
        Assert.True(radios.Adapters.Values.Single());
        Assert.Equal(SecurityEventType.PolicyTamperAttempt, Assert.Single(_events.Raised).Type);

        Assert.Equal(ControlState.NotConfigured, (await enforcer.ApplyAsync(Policy(s => s), default)).State);
        Assert.False(radios.Adapters.Values.Single());
    }

    [Theory]
    [InlineData(EnforcementMode.Enforce, ControlState.PartiallyEnforced)]
    [InlineData(EnforcementMode.Audit, ControlState.AuditOnly)]
    [InlineData(EnforcementMode.Off, ControlState.Failed)]
    public async Task Bluetooth_file_transfer_blocking_depends_on_application_control(EnforcementMode appControl, ControlState expected)
    {
        var enforcer = new BluetoothEnforcer(new InMemoryBluetooth(), _store, _events, _clock);

        var status = await enforcer.ApplyAsync(Policy(s => s with
        {
            Bluetooth = new() { Mode = BluetoothMode.BlockFileTransfer },
            ApplicationControl = new() { Mode = appControl },
        }), default);

        Assert.Equal(expected, status.State);
    }

    [Fact]
    public async Task Application_control_denies_bluetooth_file_transfer_when_asked()
    {
        var platform = new InMemoryAppControl();
        var enforcer = new AppControlEnforcer(platform, _dir.Path, _events, _clock);

        await enforcer.ApplyAsync(Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Enforce } }), default);
        Assert.Empty(platform.Policies.Values.Single().Build.DeniedFiles ?? []);

        await enforcer.ApplyAsync(Policy(s => s with { ApplicationControl = new() { Mode = EnforcementMode.Enforce }, Bluetooth = new() { Mode = BluetoothMode.BlockFileTransfer } }), default);
        Assert.Equal([BluetoothEnforcer.FileTransferProgram], platform.Policies.Values.Single().Build.DeniedFiles);
        Assert.Equal(2, platform.Deployments);
    }

    // ---------------------------------------------------------------- BitLocker recovery keys

    [Fact]
    public async Task Recovery_keys_are_sent_only_when_bitlocker_is_required_and_only_when_changed()
    {
        using var server = new FakeAgentServer();
        using var agent = new AgentHarness(server);
        agent.Inventory.RecoveryKeys.Add(new RecoveryKeyReport("C:", "{11111111-2222-3333-4444-555555555555}", "111111-222222-333333-444444-555555-666666-777777-888888"));

        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        Assert.All(server.InventoryRequests, r => Assert.Null(r.RecoveryKeys)); // not required

        server.Settings = new PolicySettings { DiskEncryption = new() { RequireBitLocker = true } };
        server.LatestVersion = 2;
        agent.Clock.Advance(TimeSpan.FromMinutes(16));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);
        agent.Clock.Advance(TimeSpan.FromMinutes(16));
        await agent.Runtime.RunOnceAsync(CancellationToken.None);

        Assert.Single(server.InventoryRequests, r => r.RecoveryKeys is { Count: 1 }); // sent once, not again while unchanged
    }
}
