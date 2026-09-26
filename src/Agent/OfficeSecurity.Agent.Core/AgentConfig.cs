using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OfficeSecurity.Agent.Core;

public enum AgentState
{
    /// <summary>Installed without server details.</summary>
    NotConfigured,

    /// <summary>Has an enrollment code; will register with the server.</summary>
    Enrolling,

    /// <summary>Registered; waiting for an administrator to approve the computer.</summary>
    PendingApproval,

    /// <summary>Approved: holds a client certificate and reports to the server.</summary>
    Enrolled,

    /// <summary>The enrollment code was refused; the agent must be installed again with a new code.</summary>
    EnrollmentFailed,

    /// <summary>An administrator rejected this computer.</summary>
    Rejected,

    /// <summary>The server no longer accepts this computer's certificate (removed from management).</summary>
    Retired,
}

/// <summary>Agent configuration. Stored in a folder only SYSTEM and Administrators can access.</summary>
public sealed record AgentConfig
{
    public AgentState State { get; init; } = AgentState.NotConfigured;

    public string? ServerAddress { get; init; }

    public string? CaCertificateBase64 { get; init; }

    /// <summary>One-time code from the dashboard; removed once used.</summary>
    public string? EnrollmentCode { get; init; }

    public Guid? ComputerId { get; init; }

    public string? PollToken { get; init; }

    /// <summary>Name of the computer's private key in the key store.</summary>
    public string? KeyName { get; init; }

    public string? CertificatePem { get; init; }

    /// <summary>Pinned policy signing key (Base64 SubjectPublicKeyInfo).</summary>
    public string? PolicySigningPublicKey { get; init; }

    public string? LastError { get; init; }

    public DateTimeOffset? LastContactUtc { get; init; }
}

/// <param name="protectDirectory">False only in tests that run without administrator rights.</param>
public sealed class AgentConfigStore(AgentPaths paths, bool protectDirectory = true)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly Lock _gate = new();

    public AgentConfig Load()
    {
        lock (_gate)
        {
            try
            {
                return File.Exists(paths.ConfigFile)
                    ? JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(paths.ConfigFile), JsonOptions) ?? new AgentConfig()
                    : new AgentConfig();
            }
            catch (JsonException)
            {
                return new AgentConfig { LastError = "Configuration file is damaged. Install the agent again." };
            }
        }
    }

    public void Save(AgentConfig config)
    {
        lock (_gate)
        {
            if (protectDirectory)
            {
                SecureDirectory.CreateAndProtect(paths.DataDirectory);
            }
            else
            {
                Directory.CreateDirectory(paths.DataDirectory);
            }

            var temp = paths.ConfigFile + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(config, JsonOptions));
            File.Move(temp, paths.ConfigFile, overwrite: true);
        }
    }
}

/// <summary>Restricts a folder to SYSTEM and Administrators; standard users cannot read or change it.</summary>
public static class SecureDirectory
{
    public static void CreateAndProtect(string directory)
    {
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows())
        {
            ApplyWindowsAcl(directory);
        }
        else
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyWindowsAcl(string directory)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        new DirectoryInfo(directory).SetAccessControl(security);
    }
}
