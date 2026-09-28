using System.Diagnostics;
using System.ServiceProcess;
using OfficeSecurity.Agent.Core;

namespace OfficeSecurity.Agent;

/// <summary>Registers the agent with the Windows Service Control Manager (sc.exe, a documented Windows tool).</summary>
internal static class ServiceInstaller
{
    public const string DisplayName = "Office Security Agent";

    // SYSTEM and Administrators: full control. Interactive/service/authenticated users: query only —
    // standard users cannot stop, pause, reconfigure or delete the service.
    private const string ServiceSecurity =
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;AU)";

    public static bool Exists()
    {
        using var controllers = new DisposableList<ServiceController>(ServiceController.GetServices());
        return controllers.Items.Any(s => string.Equals(s.ServiceName, AgentPaths.ServiceName, StringComparison.OrdinalIgnoreCase));
    }

    public static string Status()
    {
        if (!Exists())
        {
            return "not installed";
        }

        using var service = new ServiceController(AgentPaths.ServiceName);
        return service.Status.ToString();
    }

    public static void CreateOrUpdate(string executablePath)
    {
        var binPath = $"\"{executablePath}\" service";
        if (Exists())
        {
            Sc("config", AgentPaths.ServiceName, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", DisplayName);
        }
        else
        {
            Sc("create", AgentPaths.ServiceName, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", DisplayName);
        }

        Sc("description", AgentPaths.ServiceName, "Enforces office security policies and reports to the Office Security Server.");
        // Restart automatically if the process stops unexpectedly (e.g. it is killed): 5 s, 5 s, then 30 s.
        Sc("failure", AgentPaths.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000");
        Sc("failureflag", AgentPaths.ServiceName, "1");
        Sc("sdset", AgentPaths.ServiceName, ServiceSecurity);
        SetRuntimeExtractionFolder(Path.GetDirectoryName(executablePath)!);
    }

    /// <summary>
    /// The single-file program unpacks its native libraries at start-up. They go into the protected install folder
    /// (only administrators can write there, so Application Control allows them) instead of the Windows temp folder.
    /// </summary>
    private static void SetRuntimeExtractionFolder(string installDirectory)
    {
        var folder = Path.Combine(installDirectory, "runtime");
        Directory.CreateDirectory(folder);
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AgentPaths.ServiceName}", writable: true)
            ?? throw new InvalidOperationException("The service registration was not found.");
        key.SetValue("Environment", new[] { "DOTNET_BUNDLE_EXTRACT_BASE_DIR=" + folder }, Microsoft.Win32.RegistryValueKind.MultiString);
    }

    public static void Start(TimeSpan timeout)
    {
        using var service = new ServiceController(AgentPaths.ServiceName);
        if (service.Status != ServiceControllerStatus.Running)
        {
            service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, timeout);
        }
    }

    public static void Stop(TimeSpan timeout)
    {
        if (!Exists())
        {
            return;
        }

        using var service = new ServiceController(AgentPaths.ServiceName);
        if (service.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
        {
            service.Stop();
        }

        service.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
    }

    public static void Delete()
    {
        if (Exists())
        {
            Sc("delete", AgentPaths.ServiceName);
        }
    }

    private static void Sc(params string[] arguments)
    {
        var start = new ProcessStartInfo("sc.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not run sc.exe.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"sc.exe {arguments[0]} failed ({process.ExitCode}): {output.Trim()}");
        }
    }

    private sealed class DisposableList<T>(T[] items) : IDisposable
        where T : IDisposable
    {
        public T[] Items { get; } = items;

        public void Dispose()
        {
            foreach (var item in Items)
            {
                item.Dispose();
            }
        }
    }
}
