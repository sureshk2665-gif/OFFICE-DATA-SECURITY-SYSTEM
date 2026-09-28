using System.Management;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent;

/// <summary>
/// "check": compares what this computer's policy asks for with what Windows actually does right now, using real
/// attempts where possible (for example, trying to read each connected USB drive). Meant for a pilot computer:
/// plug in a USB drive or phone, connect to a Wi-Fi network, then run it. Nothing is changed.
/// </summary>
internal static class SelfCheck
{
    private static int _problems;

    public static int Run()
    {
        _problems = 0;
        var paths = new AgentPaths(AgentPaths.DefaultDataDirectory());
        var config = new AgentConfigStore(paths).Load();
        Console.WriteLine($"Office Security Agent self-check — {Environment.MachineName}, {DateTime.Now:g}");
        Console.WriteLine($"Service: {ServiceInstaller.Status()} · registration: {config.State}");

        if (config is not { ComputerId: { } computerId, PolicySigningPublicKey: { } key }
            || new PolicyCache(paths).Load(new PolicyVerifier(Convert.FromBase64String(key)), computerId) is not { IsValid: true, Document: { } policy })
        {
            Console.WriteLine("No verified policy on this computer yet (it is not approved, or has not checked in).");
            return 1;
        }

        Console.WriteLine($"Policy version {policy.Version}");
        Console.WriteLine();
        var now = DateTimeOffset.UtcNow;
        Usb(policy, now);
        Phones(policy);
        Wifi(policy);
        Bluetooth(policy);
        AppControl(policy);
        BitLocker(policy);

        Console.WriteLine();
        Console.WriteLine(_problems == 0 ? "RESULT: everything checked matches the policy." : $"RESULT: {_problems} problem(s) found — see the lines marked ✗.");
        return _problems == 0 ? 0 : 3;
    }

    private static void Usb(SecurityPolicyDocument policy, DateTimeOffset now)
    {
        Heading("USB drives and memory cards");
        var mode = policy.RemovableStorage.Mode;
        var lifted = policy.Exceptions.Any(e => e.Control == OfficeSecurity.Contracts.SecurityControl.RemovableStorage && e.IsActiveAt(now));
        var approved = ApprovedDevicesEnforcer.Active(policy, now);
        Info($"Policy: {mode}{(lifted ? " (temporarily allowed by an exception)" : string.Empty)}{(approved.Count > 0 ? $", {approved.Count} approved device(s)" : string.Empty)}");

        var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable).ToList();
        if (drives.Count == 0)
        {
            Info("No USB drive or memory card is connected. Plug one in and run this check again to test blocking.");
        }

        var usbDisks = UsbDisks();
        foreach (var drive in drives)
        {
            var readable = CanRead(drive.RootDirectory.FullName);
            var shouldBlock = mode == EnforcementMode.Enforce && !lifted && approved.Count == 0;
            var label = $"{drive.Name} ({(drive.IsReady ? drive.VolumeLabel : "not ready")})";
            if (shouldBlock)
            {
                Result(!readable, $"{label}: {(readable ? "files CAN be read — NOT blocked" : "access denied — blocked")}");
            }
            else
            {
                Info($"{label}: files {(readable ? "can" : "cannot")} be read");
            }
        }

        if (approved.Count > 0)
        {
            var allowed = ApprovedDevicesEnforcer.AllowedIds(approved);
            foreach (var disk in usbDisks)
            {
                var isApproved = allowed.Contains(disk.Id) || (disk.Parent is not null && allowed.Contains(disk.Parent));
                Result(isApproved, $"USB storage device '{disk.Name}': {(isApproved ? "approved — allowed" : "NOT approved, but it is installed and usable")}");
            }
        }
    }

    private static void Phones(SecurityPolicyDocument policy)
    {
        Heading("Phones and cameras");
        var block = policy.RemovableStorage.Mode == EnforcementMode.Enforce && policy.RemovableStorage.BlockPortableDevices;
        Info("Policy: " + (block ? "file transfer blocked" : "not blocked"));
        var phones = Wmi("SELECT Name FROM Win32_PnPEntity WHERE PNPClass = 'WPD'").Select(o => o["Name"] as string ?? "?").ToList();
        if (phones.Count == 0)
        {
            Info("No phone or camera connected. Connect one (choose 'File transfer' on the phone) and run this check again.");
        }

        foreach (var phone in phones)
        {
            Info($"Connected: {phone} — open it in File Explorer: with blocking on, Windows shows it without files or refuses access.");
        }
    }

    private static void Wifi(SecurityPolicyDocument policy)
    {
        Heading("Wi-Fi");
        var wanted = policy.Network.AllowedWifiNetworks;
        Info(wanted.Count == 0 ? "Policy: any Wi-Fi network" : "Policy: only " + string.Join(", ", wanted));
        var wifi = new WindowsWifi();
        if (!wifi.Available())
        {
            Info("This computer has no Wi-Fi.");
            return;
        }

        var (allowed, denyAll) = wifi.Filters();
        Info($"Connected to: {wifi.ConnectedNetwork() ?? "(none)"}");
        if (wanted.Count > 0)
        {
            Result(denyAll && wanted.All(w => allowed.Contains(w, StringComparer.Ordinal)),
                denyAll ? "Other Wi-Fi networks are blocked; allowed: " + string.Join(", ", allowed) : "Other Wi-Fi networks are NOT blocked");
            Info("To test: try to connect to a phone hotspot — Windows should not list or not allow it.");
        }
    }

    private static void Bluetooth(SecurityPolicyDocument policy)
    {
        Heading("Bluetooth");
        Info($"Policy: {policy.Bluetooth.Mode}");
        var radios = new WindowsBluetooth().Radios();
        if (radios.Count == 0)
        {
            Info("No Bluetooth adapter.");
            return;
        }

        foreach (var (id, disabled) in radios)
        {
            if (policy.Bluetooth.Mode == BluetoothMode.DisableRadio)
            {
                Result(disabled, $"Adapter {id}: {(disabled ? "switched off" : "ON — should be off")}");
            }
            else
            {
                Info($"Adapter {id}: {(disabled ? "switched off" : "on")}");
            }
        }
    }

    private static void AppControl(SecurityPolicyDocument policy)
    {
        Heading("Programs staff bring in (Application Control)");
        Info($"Policy: {policy.ApplicationControl.Mode}");
        if (policy.ApplicationControl.Mode == EnforcementMode.Off)
        {
            return;
        }

        var (code, output) = Tool.Run(Tool.System32("CiTool.exe"), "--list-policies", "-json");
        Result(code == 0 && output.Contains(AppControlEnforcer.PolicyName, StringComparison.Ordinal), "Office Security policy active in Windows: " + (code == 0 && output.Contains(AppControlEnforcer.PolicyName, StringComparison.Ordinal) ? "yes" : "NO"));
        Info("To test: copy a small program to the Desktop and start it — in Enforce mode Windows says it was blocked by your organisation.");
    }

    private static void BitLocker(SecurityPolicyDocument policy)
    {
        Heading("Disk encryption (BitLocker)");
        var disks = new WindowsDiskEncryption();
        if (disks.UnavailableReason() is { } reason)
        {
            Info(reason);
            return;
        }

        foreach (var (drive, isProtected) in disks.Drives())
        {
            if (policy.DiskEncryption.RequireBitLocker)
            {
                Result(isProtected, $"{drive} {(isProtected ? "encrypted" : "NOT encrypted")}");
            }
            else
            {
                Info($"{drive} {(isProtected ? "encrypted" : "not encrypted")}");
            }
        }
    }

    private static bool CanRead(string root)
    {
        try
        {
            _ = Directory.EnumerateFileSystemEntries(root).Take(1).ToList();
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private static List<(string Id, string? Parent, string Name)> UsbDisks() =>
        Wmi("SELECT PNPDeviceID, Name FROM Win32_PnPEntity WHERE PNPClass = 'DiskDrive' AND PNPDeviceID LIKE 'USBSTOR%'")
            .Select(o => o["PNPDeviceID"] as string)
            .OfType<string>()
            .Select(id => (id, DeviceList.Parent(id), id))
            .ToList();

    private static List<ManagementBaseObject> Wmi(string query)
    {
        using var searcher = new ManagementObjectSearcher(query);
        return [.. searcher.Get().Cast<ManagementBaseObject>()];
    }

    private static void Heading(string text)
    {
        Console.WriteLine();
        Console.WriteLine("== " + text);
    }

    private static void Info(string text) => Console.WriteLine("   " + text);

    private static void Result(bool ok, string text)
    {
        if (!ok)
        {
            _problems++;
        }

        Console.WriteLine((ok ? " ✓ " : " ✗ ") + text);
    }
}
