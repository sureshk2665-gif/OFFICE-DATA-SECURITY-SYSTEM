namespace OfficeSecurity.Contracts;

/// <summary>
/// Security controls enforced on office computers. Identifiers match controls C1–C18 in
/// docs/00-ARCHITECTURE-AND-PLAN.md §6. Values are persisted and must never be renumbered.
/// </summary>
public enum SecurityControl
{
    RemovableStorage = 1,
    ApprovedDevices = 2,
    PeripheralSafeguard = 3,
    MobileDeviceTransfer = 4,
    BluetoothTransfer = 5,
    ApplicationControl = 6,
    SoftwareInstallation = 7,
    ApprovedSoftwareDeployment = 8,
    NetworkRestrictions = 9,
    BrowserRestrictions = 10,
    FilePermissions = 11,
    FileAccessAudit = 12,
    ControlledFolderAccess = 13,
    DiskEncryption = 14,
    Backup = 15,
    AgentTamperProtection = 16,
    LogonRestriction = 17,
    LoginAudit = 18,
}
