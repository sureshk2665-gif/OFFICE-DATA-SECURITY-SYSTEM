using System.Security.Principal;
using System.Text.Json;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Client.Core;

namespace OfficeSecurity.Agent;

/// <summary>Command-line commands for installing and inspecting the agent on a computer.</summary>
internal static class Commands
{
    private static readonly JsonSerializerOptions PrettyJson = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static int Help(string? unknown = null)
    {
        if (unknown is not null)
        {
            Console.Error.WriteLine($"Unknown command: {unknown}");
            Console.Error.WriteLine();
        }

        Console.WriteLine("""
            Office Security Agent

            Install on this computer (run in an administrator Command Prompt or PowerShell):
              OfficeSecurity.Agent.exe install --server <address> --pairing-code <code> --enrollment-code <code>

              <address>          the server address, for example 192.168.1.20 or office-pc
              pairing code       shown by the server and in the dashboard (Computers → Add computer)
              enrollment code    one-time code from the dashboard (Computers → Add computer)

            Other commands:
              status      show whether this computer is registered and approved
              inventory   show the computer and device information the agent reports
              uninstall   remove the agent from this computer (administrator)
              run         run the agent in this window instead of as a service (troubleshooting, administrator)
            """);
        return unknown is null ? 0 : 2;
    }

    public static async Task<int> InstallAsync(string[] args)
    {
        var server = Option(args, "--server");
        var pairingCode = Option(args, "--pairing-code");
        var enrollmentCode = Option(args, "--enrollment-code");
        if (server is null || pairingCode is null || enrollmentCode is null)
        {
            Console.Error.WriteLine("install needs --server, --pairing-code and --enrollment-code.");
            return Help(null) + 2;
        }

        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Administrator rights are required. Right-click Command Prompt, choose \"Run as administrator\", and run the command again.");
            return 5;
        }

        Console.WriteLine("Checking the server and pairing code...");
        var pairing = await PairingService.PairAsync(server, pairingCode);
        if (!pairing.Success)
        {
            Console.Error.WriteLine(pairing.Error);
            return 3;
        }

        Console.WriteLine($"Server verified: {pairing.Settings!.ServerAddress}");

        ServiceInstaller.Stop(TimeSpan.FromSeconds(30));

        // Copy the program to Program Files (only administrators can change it there).
        var target = AgentPaths.InstalledExecutablePath();
        var source = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine the program location.");
        if (!string.Equals(Path.GetFullPath(source), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(source, target, overwrite: true);
        }

        // A fresh identity for this installation: old key and cached policy are removed.
        var paths = new AgentPaths(AgentPaths.DefaultDataDirectory());
        SecureDirectory.CreateAndProtect(paths.DataDirectory);
        var store = new AgentConfigStore(paths);
        var previous = store.Load();
        if (previous.KeyName is not null)
        {
            new CngDeviceKeyStore().Delete(previous.KeyName);
        }

        File.Delete(paths.PolicyCacheFile);
        store.Save(new AgentConfig
        {
            State = AgentState.Enrolling,
            ServerAddress = pairing.Settings.ServerAddress,
            CaCertificateBase64 = pairing.Settings.CaCertificateBase64,
            EnrollmentCode = enrollmentCode.Trim(),
        });

        ServiceInstaller.CreateOrUpdate(target);
        ServiceInstaller.Start(TimeSpan.FromSeconds(60));
        Console.WriteLine("Service installed and started (starts automatically with Windows).");

        Console.WriteLine("Registering with the server...");
        for (var i = 0; i < 90; i++)
        {
            var config = store.Load();
            switch (config.State)
            {
                case AgentState.PendingApproval or AgentState.Enrolled:
                    Console.WriteLine($"Registered. Computer id: {config.ComputerId}");
                    Console.WriteLine("Now approve this computer in the Administrator Dashboard (Computers).");
                    return 0;
                case AgentState.EnrollmentFailed:
                    Console.Error.WriteLine(config.LastError);
                    return 4;
            }

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        Console.Error.WriteLine("The service is running but has not registered yet. Check 'OfficeSecurity.Agent.exe status' in a minute.");
        return 6;
    }

    public static int Uninstall()
    {
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Administrator rights are required to remove the agent.");
            return 5;
        }

        ServiceInstaller.Stop(TimeSpan.FromSeconds(30));
        ServiceInstaller.Delete();

        var paths = new AgentPaths(AgentPaths.DefaultDataDirectory());

        // Give the computer back its normal Windows behaviour: remove exactly the settings the agent made.
        var settings = new RegistryPolicyEngine(new WindowsPolicyRegistry(), new FileManagedSettingsStore(paths.DataDirectory)).RemoveAll();
        var rules = FirewallEnforcer.RemoveAll(new WindowsFirewall(), new FileManagedSettingsStore(paths.DataDirectory, FileManagedSettingsStore.FirewallFile));
        var auditStore = new FileManagedSettingsStore(paths.DataDirectory, FileManagedSettingsStore.AuditFile);
        var folders = FileAccessAuditEnforcer.RemoveAll(new WindowsFolderAudit(), auditStore);
        var audit = new AuditPolicyEngine(new WindowsAuditPolicy(), auditStore).RemoveAll();
        var appControl = AppControlEnforcer.RemoveAll(new WindowsAppControl(Path.Combine(paths.DataDirectory, "appcontrol")), paths.DataDirectory);
        Console.WriteLine($"Removed the protections set by the agent ({settings} Windows setting(s), {rules} firewall rule(s), {audit} audit setting(s), " +
            $"{folders} folder audit entr(ies){(appControl ? ", the Application Control policy" : string.Empty)}).");
        var config = new AgentConfigStore(paths).Load();
        if (config.KeyName is not null)
        {
            new CngDeviceKeyStore().Delete(config.KeyName);
        }

        TryDelete(paths.DataDirectory);
        var installDirectory = AgentPaths.DefaultInstallDirectory();
        var runningFromInstall = Environment.ProcessPath is { } self && Path.GetFullPath(self).StartsWith(Path.GetFullPath(installDirectory), StringComparison.OrdinalIgnoreCase);
        if (!runningFromInstall)
        {
            TryDelete(installDirectory);
        }

        Console.WriteLine("The Office Security Agent has been removed from this computer.");
        Console.WriteLine("Also remove the computer in the dashboard (Computers → Remove from management).");
        return 0;
    }

    public static async Task<int> StatusAsync()
    {
        Console.WriteLine($"Service: {ServiceInstaller.Status()}");
        if (IsAdministrator())
        {
            var config = new AgentConfigStore(new AgentPaths(AgentPaths.DefaultDataDirectory())).Load();
            Console.WriteLine($"State: {config.State}");
            Console.WriteLine($"Server: {config.ServerAddress ?? "-"}");
            Console.WriteLine($"Computer id: {config.ComputerId?.ToString() ?? "-"}");
            Console.WriteLine($"Last contact: {config.LastContactUtc?.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture) ?? "-"}");
            if (config.LastError is not null)
            {
                Console.WriteLine($"Last problem: {config.LastError}");
            }

            return 0;
        }

        var status = await AgentLocalClient.TryGetStatusAsync();
        Console.WriteLine(status is null ? "The agent is not running." : $"State: {status.State}\n{status.Message}");
        return 0;
    }

    public static int Inventory()
    {
        var collector = new WindowsInventoryCollector();
        Console.WriteLine(JsonSerializer.Serialize(new { hardware = collector.CollectHardware(), devices = collector.CollectDevices(), software = collector.CollectSoftware() }, PrettyJson));
        return 0;
    }

    private static string? Option(string[] args, string name)
    {
        var index = Array.FindIndex(args, a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Could not delete {directory}: {ex.Message}");
        }
    }
}
