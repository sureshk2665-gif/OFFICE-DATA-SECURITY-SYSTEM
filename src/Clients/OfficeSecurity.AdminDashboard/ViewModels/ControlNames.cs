using OfficeSecurity.Contracts;

namespace OfficeSecurity.AdminDashboard.ViewModels;

/// <summary>Plain-language names for security controls and their states.</summary>
public static class ControlNames
{
    public static string Of(SecurityControl control) => control switch
    {
        SecurityControl.RemovableStorage => "USB drives and memory cards",
        SecurityControl.ApprovedDevices => "Approved USB devices",
        SecurityControl.PeripheralSafeguard => "Keyboards, mice and printers kept working",
        SecurityControl.MobileDeviceTransfer => "Phones and cameras (file transfer)",
        SecurityControl.BluetoothTransfer => "Bluetooth file transfer",
        SecurityControl.ApplicationControl => "Application Control (unapproved programs)",
        SecurityControl.SoftwareInstallation => "Software installation by staff",
        SecurityControl.ApprovedSoftwareDeployment => "Approved software installation",
        SecurityControl.NetworkRestrictions => "Programs blocked from the network",
        SecurityControl.BrowserRestrictions => "Website restrictions",
        SecurityControl.FilePermissions => "Company folder permissions",
        SecurityControl.FileAccessAudit => "File access records",
        SecurityControl.ControlledFolderAccess => "Ransomware protection",
        SecurityControl.DiskEncryption => "Disk encryption (BitLocker)",
        SecurityControl.Backup => "Backup",
        SecurityControl.AgentTamperProtection => "Agent self-protection",
        SecurityControl.LogonRestriction => "Windows sign-in restriction",
        SecurityControl.LoginAudit => "Windows sign-in records",
        _ => control.ToString(),
    };

    public static string Of(ControlState state) => state switch
    {
        ControlState.Enforced => "On (verified)",
        ControlState.PartiallyEnforced => "Partly on",
        ControlState.AuditOnly => "Audit only — not blocking",
        ControlState.NotConfigured => "Off",
        ControlState.NotImplemented => "Not available yet",
        ControlState.TemporarilyAllowed => "Temporarily allowed",
        ControlState.Failed => "FAILED",
        ControlState.NotSupportedOnEdition => "Not supported on this Windows edition",
        _ => "Not checked yet",
    };
}

/// <summary>A row of the "Security protections" table on a computer's page.</summary>
public sealed record ControlRow(string Name, string State, string? Details, bool NeedsAttention);

/// <summary>A choice in the "lift temporarily" drop-downs.</summary>
public sealed record NamedChoice<T>(T Value, string Label);
