namespace OfficeSecurity.Policy;

/// <summary>
/// The part of a security policy an administrator edits. The server combines it with a computer's
/// identity, version and exemptions into a signed <see cref="SecurityPolicyDocument"/>.
/// </summary>
public sealed record PolicySettings
{
    public RemovableStorageSettings RemovableStorage { get; init; } = new();

    public BluetoothSettings Bluetooth { get; init; } = new();

    public ApplicationControlSettings ApplicationControl { get; init; } = new();

    public SoftwareInstallationSettings SoftwareInstallation { get; init; } = new();

    public NetworkSettings Network { get; init; } = new();

    public BrowserSettings Browser { get; init; } = new();

    public FileProtectionSettings FileProtection { get; init; } = new();

    public AgentSettings Agent { get; init; } = new();

    public SecurityPolicyDocument ToDocument(Guid computerId, long version, DateTimeOffset issuedAtUtc, IReadOnlyList<PolicyExemption>? exemptions = null) => new()
    {
        ComputerId = computerId,
        Version = version,
        IssuedAtUtc = issuedAtUtc,
        RemovableStorage = RemovableStorage,
        Bluetooth = Bluetooth,
        ApplicationControl = ApplicationControl,
        SoftwareInstallation = SoftwareInstallation,
        Network = Network,
        Browser = Browser,
        FileProtection = FileProtection,
        Agent = Agent,
        Exceptions = exemptions ?? [],
    };

    /// <summary>Validation errors for these settings (the same rules applied to signed documents).</summary>
    public IReadOnlyList<string> Validate() =>
        PolicyDocumentValidator.Validate(ToDocument(Guid.NewGuid(), 1, DateTimeOffset.UnixEpoch));
}

public sealed record PolicySummary(
    Guid Id,
    string Name,
    string? Description,
    bool IsDefault,
    int Revision,
    int ComputerCount,
    DateTimeOffset UpdatedAtUtc);

public sealed record PolicyDetail(
    Guid Id,
    string Name,
    string? Description,
    bool IsDefault,
    int Revision,
    PolicySettings Settings,
    DateTimeOffset UpdatedAtUtc);

public sealed record SavePolicyRequest(string Name, string? Description, PolicySettings Settings);
