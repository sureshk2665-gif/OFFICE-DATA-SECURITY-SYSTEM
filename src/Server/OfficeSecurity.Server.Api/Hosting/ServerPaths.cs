namespace OfficeSecurity.Server.Api.Hosting;

/// <summary>Locations of the server's data. Everything lives under one directory for simple backup.</summary>
public sealed class ServerPaths
{
    public ServerPaths(string dataDirectory)
    {
        DataDirectory = Path.GetFullPath(dataDirectory);
    }

    public string DataDirectory { get; }

    public string DatabaseFile => Path.Combine(DataDirectory, "office-security.db");

    public string KeysDirectory => Path.Combine(DataDirectory, "keys");

    public string CertificatesDirectory => Path.Combine(DataDirectory, "certificates");

    /// <summary>Approved installer files.</summary>
    public string PackagesDirectory => Path.Combine(DataDirectory, "packages");

    /// <summary>Written only while no administrator exists; deleted after the first administrator is set up.</summary>
    public string FirstAdminSetupCodeFile => Path.Combine(DataDirectory, "FIRST-ADMIN-SETUP-CODE.txt");

    /// <summary>Non-secret information needed to connect clients (addresses and pairing code).</summary>
    public string ConnectionInfoFile => Path.Combine(DataDirectory, "SERVER-CONNECTION-INFO.txt");

    public static string DefaultDataDirectory() =>
        OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OfficeSecurity", "Server")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OfficeSecurity", "Server");
}
