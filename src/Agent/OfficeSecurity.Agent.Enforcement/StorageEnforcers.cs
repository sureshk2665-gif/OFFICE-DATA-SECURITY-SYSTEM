using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>
/// Windows "Removable Storage Access" policies (Computer Configuration > Administrative Templates > System >
/// Removable Storage Access; RemovableStorage.admx). They apply to every user, including administrators.
/// </summary>
public static class RemovableStoragePolicy
{
    public const string Root = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";

    /// <summary>"Removable Disks" (USB drives, memory cards).</summary>
    public const string RemovableDisks = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";

    /// <summary>"CD and DVD".</summary>
    public const string CdAndDvd = "{53f56308-b6bf-11d0-94f2-00a0c91efb8b}";

    /// <summary>"Floppy Drives".</summary>
    public const string FloppyDrives = "{53f56311-b6bf-11d0-94f2-00a0c91efb8b}";

    /// <summary>"Tape Drives".</summary>
    public const string TapeDrives = "{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}";

    /// <summary>"WPD Devices" (phones, cameras and media players using MTP/PTP): two device interface classes.</summary>
    public static readonly IReadOnlyList<string> WpdDevices = ["{6AC27878-A6FA-4155-BA85-F98F491D4F33}", "{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}"];

    public static IEnumerable<PolicyValue> Deny(string deviceClass, bool execute = false)
    {
        yield return new PolicyValue($@"{Root}\{deviceClass}", "Deny_Read", 1);
        yield return new PolicyValue($@"{Root}\{deviceClass}", "Deny_Write", 1);
        if (execute)
        {
            yield return new PolicyValue($@"{Root}\{deviceClass}", "Deny_Execute", 1);
        }
    }
}

/// <summary>Blocks USB drives, memory cards and (optionally) CD/DVD drives.</summary>
public sealed class RemovableStorageEnforcer(RegistryPolicyEngine engine, IEnforcementEvents events, TimeProvider clock)
    : RegistryPolicyEnforcer(engine, events, clock)
{
    private readonly TimeProvider _clock = clock;

    public override SecurityControl Control => SecurityControl.RemovableStorage;

    protected override string Description => "USB drive blocking";

    protected override RegistryPlan Plan(SecurityPolicyDocument policy)
    {
        var settings = policy.RemovableStorage;
        switch (settings.Mode)
        {
            case EnforcementMode.Audit:
                return new RegistryPlan(ControlState.AuditOnly, "Audit mode: USB drives are allowed; every connection is recorded.", []);
            case EnforcementMode.Enforce:
                // With approved devices, USB drives are controlled per device by the device installation policy
                // (ApprovedDevicesEnforcer); running programs from any USB drive stays denied.
                var perDevice = ApprovedDevicesEnforcer.Active(policy, _clock.GetUtcNow()).Count > 0;
                var disks = perDevice
                    ? [new PolicyValue($@"{RemovableStoragePolicy.Root}\{RemovableStoragePolicy.RemovableDisks}", "Deny_Execute", 1)]
                    : RemovableStoragePolicy.Deny(RemovableStoragePolicy.RemovableDisks, execute: true);
                var values = disks
                    .Concat(RemovableStoragePolicy.Deny(RemovableStoragePolicy.FloppyDrives))
                    .Concat(RemovableStoragePolicy.Deny(RemovableStoragePolicy.TapeDrives));
                if (settings.BlockOpticalDrives)
                {
                    values = values.Concat(RemovableStoragePolicy.Deny(RemovableStoragePolicy.CdAndDvd));
                }

                return new RegistryPlan(ControlState.Enforced,
                    perDevice
                        ? "Only approved USB drives can be used (see 'Approved USB devices'); running programs from USB drives" + (settings.BlockOpticalDrives ? " and CD/DVD access" : string.Empty) + " are denied for all users."
                        : "Reading, writing and running programs from USB drives and memory cards" + (settings.BlockOpticalDrives ? ", and CD/DVD access," : string.Empty)
                          + " are denied for all users (Windows Removable Storage Access policy). A drive that was already connected must be reconnected.",
                    values.ToList());
            default:
                return RegistryPlan.NotConfigured();
        }
    }
}

/// <summary>Blocks file transfer with phones, cameras and media players (MTP/PTP).</summary>
public sealed class MobileDeviceTransferEnforcer(RegistryPolicyEngine engine, IEnforcementEvents events, TimeProvider clock)
    : RegistryPolicyEnforcer(engine, events, clock)
{
    public override SecurityControl Control => SecurityControl.MobileDeviceTransfer;

    protected override string Description => "Phone transfer blocking";

    protected override RegistryPlan Plan(SecurityPolicyDocument policy)
    {
        var settings = policy.RemovableStorage;
        if (!settings.BlockPortableDevices || settings.Mode == EnforcementMode.Off)
        {
            return RegistryPlan.NotConfigured();
        }

        return settings.Mode == EnforcementMode.Audit
            ? new RegistryPlan(ControlState.AuditOnly, "Audit mode: phones are allowed; every connection is recorded.", [])
            : new RegistryPlan(ControlState.Enforced,
                "File transfer with phones, cameras and media players (MTP/PTP) is denied for all users (Windows Removable Storage Access policy). "
                + "Charging still works. A phone that was already connected must be reconnected.",
                RemovableStoragePolicy.WpdDevices.SelectMany(c => RemovableStoragePolicy.Deny(c)).ToList());
    }
}

/// <summary>Stops staff installing programs for themselves with Windows Installer, and installing packaged apps.</summary>
public sealed class SoftwareInstallationEnforcer(RegistryPolicyEngine engine, IEnforcementEvents events, TimeProvider clock)
    : RegistryPolicyEnforcer(engine, events, clock)
{
    public const string InstallerKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
    public const string AppxKey = @"SOFTWARE\Policies\Microsoft\Windows\Appx";

    public override SecurityControl Control => SecurityControl.SoftwareInstallation;

    protected override string Description => "Software installation restriction";

    protected override RegistryPlan Plan(SecurityPolicyDocument policy) => !policy.SoftwareInstallation.BlockStaffInstalls
        ? RegistryPlan.NotConfigured()
        : new RegistryPlan(ControlState.PartiallyEnforced,
            "Blocked: Windows Installer (MSI) installations started by staff (\"Turn off Windows Installer: for non-managed applications only\") and packaged (Store/AppX) app installations by standard users. "
            + "Standard Windows accounts already cannot install programs for all users. NOT blocked yet: portable programs and "
            + "EXE installers that install into the user's own folders — that needs Application Control.",
            [
                // "Turn off Windows Installer" (MSI.admx, DisableMSI): 1 = "For non-managed applications only".
                new PolicyValue(InstallerKey, "DisableMSI", 1),
                // "Prevent non-admin users from installing packaged Windows apps" (AppxPackageManager.admx).
                new PolicyValue(AppxKey, "BlockNonAdminUserInstall", 1),
            ]);
}
