using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>What Windows reports for a deployed App Control policy.</summary>
public sealed record AppControlPolicyState(bool IsActive, string? Version);

/// <summary>The App Control policy to build: Microsoft's "Allow Microsoft" base plus folder rules.</summary>
public sealed record AppControlBuild(bool AuditOnly, IReadOnlyList<string> AllowedFolders, string Version, IReadOnlyList<string>? DeniedFiles = null);

/// <summary>Windows App Control for Business (WDAC): build, activate, query and remove a policy.</summary>
public interface IAppControlPlatform
{
    /// <summary>Null when this computer can use App Control; otherwise why not.</summary>
    string? UnsupportedReason();

    AppControlPolicyState? Query(Guid policyId);

    void Deploy(Guid policyId, AppControlBuild build);

    void Remove(Guid policyId);
}

/// <summary>
/// Application Control: programs may run only if they are part of Windows, signed by Microsoft, or installed in
/// Program Files (or an administrator-approved folder). Programs brought in by users (Downloads, Desktop, USB
/// drives, AppData...) are blocked (Enforce) or only reported (Audit).
/// </summary>
public sealed class AppControlEnforcer(IAppControlPlatform platform, string stateDirectory, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    public const string PolicyName = "Office Security System";

    /// <summary>Folders where only administrators can install programs.</summary>
    public static readonly IReadOnlyList<string> AdministratorFolders = [@"%OSDRIVE%\Program Files\*", @"%OSDRIVE%\Program Files (x86)\*"];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public SecurityControl Control => SecurityControl.ApplicationControl;

    private string StatePath => Path.Combine(stateDirectory, "app-control.json");

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var settings = policy.ApplicationControl;
        var state = LoadState();

        if (settings.Mode == EnforcementMode.Off)
        {
            if (state.PolicyId is { } id && state.DeployedHash is not null)
            {
                if (platform.Query(id) is not null)
                {
                    platform.Remove(id);
                }

                SaveState(state with { DeployedHash = null });
            }

            return Task.FromResult(Status(ControlState.NotConfigured, "Not required by the policy."));
        }

        if (platform.UnsupportedReason() is { } reason)
        {
            return Task.FromResult(Status(ControlState.NotSupportedOnEdition, reason));
        }

        var folders = Folders(settings);
        var denied = Denied(policy);
        var hash = Hash(settings.Mode, [.. folders, .. denied.Select(d => "deny:" + d)]);
        var policyId = state.PolicyId ?? Guid.NewGuid();
        var current = platform.Query(policyId);
        var inPlace = current is { IsActive: true } && state.DeployedHash == hash && SameVersion(current.Version, state.Version);
        if (!inPlace)
        {
            if (state.DeployedHash == hash)
            {
                events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                    "Application Control: the policy had been removed or replaced outside this system and was restored.");
            }

            var next = state.Revision + 1;
            var version = string.Create(CultureInfo.InvariantCulture, $"10.0.{next / 60000}.{next % 60000}");
            SaveState(state with { PolicyId = policyId, Revision = next, Version = version, DeployedHash = null });
            platform.Deploy(policyId, new AppControlBuild(settings.Mode == EnforcementMode.Audit, folders, version, denied));
            state = state with { PolicyId = policyId, Revision = next, Version = version, DeployedHash = hash };
            SaveState(state);
            current = platform.Query(policyId);
        }

        return Task.FromResult(Result(settings.Mode, folders, current, state));
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var settings = policy.ApplicationControl;
        var state = LoadState();
        if (settings.Mode == EnforcementMode.Off)
        {
            return Task.FromResult(Status(ControlState.NotConfigured, "Not required by the policy."));
        }

        if (platform.UnsupportedReason() is { } reason)
        {
            return Task.FromResult(Status(ControlState.NotSupportedOnEdition, reason));
        }

        return Task.FromResult(Result(settings.Mode, Folders(settings), state.PolicyId is { } id ? platform.Query(id) : null, state));
    }

    /// <summary>Removes the policy this system deployed (used when the agent is uninstalled).</summary>
    public static bool RemoveAll(IAppControlPlatform platform, string stateDirectory)
    {
        ArgumentNullException.ThrowIfNull(platform);
        var path = Path.Combine(stateDirectory, "app-control.json");
        if (!File.Exists(path) || JsonSerializer.Deserialize<AppControlState>(File.ReadAllText(path)) is not { PolicyId: { } id })
        {
            return false;
        }

        var removed = platform.Query(id) is not null;
        if (removed)
        {
            platform.Remove(id);
        }

        File.Delete(path);
        return removed;
    }

    private ControlStatus Result(EnforcementMode mode, List<string> folders, AppControlPolicyState? current, AppControlState state)
    {
        if (current is not { IsActive: true } || !SameVersion(current.Version, state.Version))
        {
            return Status(ControlState.Failed, $"Windows does not report the Application Control policy as active (expected version {state.Version}, found {current?.Version ?? "none"}).");
        }

        var allowed = "Allowed: Windows, programs signed by Microsoft, and programs installed in Program Files"
            + (folders.Count > AdministratorFolders.Count ? " or the approved folders" : string.Empty) + ".";
        return mode == EnforcementMode.Audit
            ? Status(ControlState.AuditOnly, $"Audit mode: nothing is blocked; programs that would be blocked are reported. {allowed}")
            : Status(ControlState.Enforced, $"Other programs (for example from Downloads, the Desktop, AppData or a USB drive) are blocked by Windows App Control. {allowed} Scripts are not restricted.");
    }

    /// <summary>Programs always blocked, even though Microsoft signs them (e.g. Bluetooth file transfer).</summary>
    private static List<string> Denied(SecurityPolicyDocument policy) =>
        policy.Bluetooth.Mode == BluetoothMode.BlockFileTransfer ? [BluetoothEnforcer.FileTransferProgram] : [];

    private static List<string> Folders(ApplicationControlSettings settings) =>
        [.. AdministratorFolders, .. settings.AllowedFolders.Select(f => f.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)];

    private static string Hash(EnforcementMode mode, List<string> folders) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(mode + "|" + string.Join("|", folders).ToUpperInvariant())));

    private static bool SameVersion(string? a, string? b) =>
        a is not null && b is not null && Version.TryParse(a, out var va) && Version.TryParse(b, out var vb) ? va == vb : string.Equals(a, b, StringComparison.Ordinal);

    private ControlStatus Status(ControlState state, string detail) => new(Control, state, detail, clock.GetUtcNow());

    private AppControlState LoadState()
    {
        try
        {
            return File.Exists(StatePath) ? JsonSerializer.Deserialize<AppControlState>(File.ReadAllText(StatePath)) ?? new() : new();
        }
        catch (JsonException)
        {
            return new();
        }
    }

    private void SaveState(AppControlState state)
    {
        Directory.CreateDirectory(stateDirectory);
        File.WriteAllText(StatePath + ".tmp", JsonSerializer.Serialize(state, Json));
        File.Move(StatePath + ".tmp", StatePath, overwrite: true);
    }

    /// <summary>What this system deployed: a stable policy id, a revision counter and the settings' fingerprint.</summary>
    private sealed record AppControlState
    {
        public Guid? PolicyId { get; init; }

        public int Revision { get; init; }

        public string? Version { get; init; }

        public string? DeployedHash { get; init; }
    }
}

/// <summary>An in-memory App Control platform for tests.</summary>
public sealed class InMemoryAppControl : IAppControlPlatform
{
    public Dictionary<Guid, (AppControlBuild Build, bool Active)> Policies { get; } = [];

    public string? Unsupported { get; set; }

    public int Deployments { get; private set; }

    public string? UnsupportedReason() => Unsupported;

    public AppControlPolicyState? Query(Guid policyId) =>
        Policies.TryGetValue(policyId, out var p) ? new AppControlPolicyState(p.Active, p.Build.Version) : null;

    public void Deploy(Guid policyId, AppControlBuild build)
    {
        Deployments++;
        Policies[policyId] = (build, true);
    }

    public void Remove(Guid policyId) => Policies.Remove(policyId);
}
