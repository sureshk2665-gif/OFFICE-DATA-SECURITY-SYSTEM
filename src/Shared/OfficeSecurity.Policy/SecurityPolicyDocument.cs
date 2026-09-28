namespace OfficeSecurity.Policy;

/// <summary>
/// The effective security policy for one computer, produced by the server and signed with the
/// policy-signing key. Agents enforce exactly this document; they never merge policies themselves.
/// </summary>
public sealed record SecurityPolicyDocument
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>Monotonically increasing per computer. Agents reject a lower or equal version.</summary>
    public required long Version { get; init; }

    public required Guid ComputerId { get; init; }

    public required DateTimeOffset IssuedAtUtc { get; init; }

    public RemovableStorageSettings RemovableStorage { get; init; } = new();

    public BluetoothSettings Bluetooth { get; init; } = new();

    public ApplicationControlSettings ApplicationControl { get; init; } = new();

    public SoftwareInstallationSettings SoftwareInstallation { get; init; } = new();

    public NetworkSettings Network { get; init; } = new();

    public BrowserSettings Browser { get; init; } = new();

    public FileProtectionSettings FileProtection { get; init; } = new();

    public SignInAuditSettings SignInAudit { get; init; } = new();

    public DiskEncryptionSettings DiskEncryption { get; init; } = new();

    public AgentSettings Agent { get; init; } = new();

    /// <summary>Time-boxed administrator-approved exceptions.</summary>
    public IReadOnlyList<PolicyExemption> Exceptions { get; init; } = [];
}

public enum EnforcementMode
{
    /// <summary>Control is not managed by this system.</summary>
    Off = 0,

    /// <summary>Violations are logged but not blocked (used before switching to enforce).</summary>
    Audit = 1,

    /// <summary>Violations are blocked and logged.</summary>
    Enforce = 2,
}

public sealed record RemovableStorageSettings
{
    public EnforcementMode Mode { get; init; } = EnforcementMode.Off;

    /// <summary>Block phones and cameras using MTP/PTP (Windows Portable Devices).</summary>
    public bool BlockPortableDevices { get; init; } = true;

    public bool BlockOpticalDrives { get; init; } = true;

    public IReadOnlyList<ApprovedDevice> ApprovedDevices { get; init; } = [];
}

/// <summary>
/// A USB storage device approved by an administrator, identified by its Windows device instance ID (the disk) and
/// the instance ID of the USB device it belongs to (what Windows' device installation policy matches).
/// </summary>
public sealed record ApprovedDevice(string DeviceInstanceId, string Description, DateTimeOffset? ExpiresAtUtc, string? ParentInstanceId = null)
{
    public bool IsActiveAt(DateTimeOffset nowUtc) => ExpiresAtUtc is null || ExpiresAtUtc > nowUtc;
}

public enum BluetoothMode
{
    Allow = 0,

    /// <summary>Block file transfer (OBEX) but keep keyboards, mice and headsets.</summary>
    BlockFileTransfer = 1,

    /// <summary>Disable the Bluetooth radio completely.</summary>
    DisableRadio = 2,
}

public sealed record BluetoothSettings
{
    public BluetoothMode Mode { get; init; } = BluetoothMode.Allow;
}

public sealed record ApplicationControlSettings
{
    public EnforcementMode Mode { get; init; } = EnforcementMode.Off;

    /// <summary>Deny execution from folders a standard user can write to (Downloads, AppData, Temp...).</summary>
    public bool BlockUserWritableLocations { get; init; } = true;

    /// <summary>Code-signing publishers allowed to run. Not used yet (programs installed in Program Files are allowed).</summary>
    public IReadOnlyList<string> AllowedPublishers { get; init; } = [];

    /// <summary>SHA-256 hashes (hex) of individually approved unsigned executables. Not used yet.</summary>
    public IReadOnlyList<string> AllowedFileHashes { get; init; } = [];

    /// <summary>
    /// Extra folders (besides Program Files and Windows) from which programs may run, e.g. "D:\CompanyApps\*".
    /// Windows only honours a folder that standard users cannot write to.
    /// </summary>
    public IReadOnlyList<string> AllowedFolders { get; init; } = [];
}

/// <summary>Windows sign-in records (who signed in to the computer, failed sign-ins, sign-outs).</summary>
public sealed record SignInAuditSettings
{
    public bool RecordWindowsSignIns { get; init; }
}

/// <summary>Disk encryption requirement (checked and reported; BitLocker is not switched on automatically).</summary>
public sealed record DiskEncryptionSettings
{
    public bool RequireBitLocker { get; init; }
}

public sealed record SoftwareInstallationSettings
{
    /// <summary>
    /// Stop standard users installing Windows Installer (MSI) programs for themselves and installing packaged
    /// (Store/AppX) apps. Installations by administrators and by this system are not affected.
    /// </summary>
    public bool BlockStaffInstalls { get; init; }
}

public sealed record NetworkSettings
{
    /// <summary>Full paths of programs denied outbound network access by Windows Firewall.</summary>
    public IReadOnlyList<string> BlockedApplicationPaths { get; init; } = [];

    /// <summary>When non-empty, only these Wi-Fi network names may be used (blocks phone hotspots). Not enforced yet.</summary>
    public IReadOnlyList<string> AllowedWifiNetworks { get; init; } = [];
}

/// <summary>
/// Applied to Microsoft Edge, Google Chrome and Mozilla Firefox through their documented policies. URL patterns
/// use the Chromium URL filter format ("example.com", "*.example.com" is not needed: "example.com" covers
/// subdomains; "*" means every site).
/// </summary>
public sealed record BrowserSettings
{
    public IReadOnlyList<string> BlockedUrls { get; init; } = [];

    public IReadOnlyList<string> AllowedUrls { get; init; } = [];

    public bool DisablePrivateBrowsing { get; init; }
}

public sealed record FileProtectionSettings
{
    public IReadOnlyList<ProtectedFolder> ProtectedFolders { get; init; } = [];
}

public sealed record ProtectedFolder(string Path, bool AuditAccess, bool ControlledFolderAccess);

public sealed record AgentSettings
{
    public int HeartbeatIntervalSeconds { get; init; } = 60;

    public int EventUploadIntervalSeconds { get; init; } = 30;
}

/// <summary>An administrator-approved, time-limited exception to one control.</summary>
public sealed record PolicyExemption(Guid Id, OfficeSecurity.Contracts.SecurityControl Control, string Reason, DateTimeOffset StartsAtUtc, DateTimeOffset ExpiresAtUtc)
{
    public bool IsActiveAt(DateTimeOffset nowUtc) => nowUtc >= StartsAtUtc && nowUtc < ExpiresAtUtc;
}
