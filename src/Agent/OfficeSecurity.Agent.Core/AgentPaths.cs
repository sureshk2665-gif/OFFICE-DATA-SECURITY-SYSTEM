namespace OfficeSecurity.Agent.Core;

/// <summary>Where the agent keeps its configuration, cached policy and event queue.</summary>
public sealed class AgentPaths(string dataDirectory)
{
    public const string ServiceName = "OfficeSecurityAgent";

    public string DataDirectory { get; } = Path.GetFullPath(dataDirectory);

    public string ConfigFile => Path.Combine(DataDirectory, "agent.json");

    public string PolicyCacheFile => Path.Combine(DataDirectory, "policy.json");

    public string EventQueueFile => Path.Combine(DataDirectory, "events.db");

    /// <summary>Written by an authorised uninstall just before it stops the service (see AgentRuntime.NotifyStoppingAsync).</summary>
    public string UninstallMarkerFile => Path.Combine(DataDirectory, "uninstalling");

    public string FileKeyDirectory => Path.Combine(DataDirectory, "keys");

    public static string DefaultDataDirectory() =>
        OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OfficeSecurity", "Agent")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OfficeSecurity", "Agent");

    /// <summary>Install location of the agent program; only administrators can write there.</summary>
    public static string DefaultInstallDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OfficeSecurity", "Agent");

    public static string InstalledExecutablePath() => OfficeSecurity.Contracts.AgentLocalProtocol.InstalledAgentExecutable();
}
