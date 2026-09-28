using System.Globalization;
using System.Management;
using Microsoft.Win32;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent;

/// <summary>Computer and device information from WMI and the registry (documented Windows interfaces).</summary>
internal sealed class WindowsInventoryCollector : IInventoryCollector
{
    // Removable storage (USB disks and card readers), phones/cameras (MTP/PTP), optical drives and Bluetooth.
    private const string DeviceQuery =
        "SELECT PNPDeviceID, Name, PNPClass, Manufacturer FROM Win32_PnPEntity WHERE " +
        "PNPClass = 'WPD' OR PNPClass = 'Bluetooth' OR PNPClass = 'CDROM' OR " +
        "(PNPClass = 'DiskDrive' AND (PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'SCSI%USB%' OR PNPDeviceID LIKE 'SD%'))";

    public HardwareInventory CollectHardware()
    {
        var os = First("SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem");
        var system = First("SELECT Manufacturer, Model, TotalPhysicalMemory, PartOfDomain, Domain, Workgroup FROM Win32_ComputerSystem");
        var bios = First("SELECT SerialNumber FROM Win32_BIOS");
        var cpu = First("SELECT Name FROM Win32_Processor");
        using var version = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

        var build = version?.GetValue("CurrentBuild") as string;
        var ubr = version?.GetValue("UBR");
        var partOfDomain = system?.GetValueOrDefault("PartOfDomain") as bool?;

        return new HardwareInventory(
            Environment.MachineName,
            os?.GetValueOrDefault("Caption") as string,
            version?.GetValue("DisplayVersion") as string ?? os?.GetValueOrDefault("Version") as string,
            build is null ? os?.GetValueOrDefault("BuildNumber") as string : ubr is null ? build : $"{build}.{Convert.ToString(ubr, CultureInfo.InvariantCulture)}",
            version?.GetValue("EditionID") as string,
            system?.GetValueOrDefault("Manufacturer") as string,
            system?.GetValueOrDefault("Model") as string,
            bios?.GetValueOrDefault("SerialNumber") as string,
            (cpu?.GetValueOrDefault("Name") as string)?.Trim(),
            system?.GetValueOrDefault("TotalPhysicalMemory") is ulong bytes ? (long)(bytes / (1024 * 1024)) : null,
            SystemDiskGb(),
            TpmPresent(),
            partOfDomain,
            partOfDomain == true ? system?.GetValueOrDefault("Domain") as string : system?.GetValueOrDefault("Workgroup") as string);
    }

    public IReadOnlyList<RecoveryKeyReport> CollectRecoveryKeys() => WindowsRecoveryKeys.Read();

    public IReadOnlyList<ConnectedDevice> CollectDevices()
    {
        using var searcher = new ManagementObjectSearcher(DeviceQuery);
        using var results = searcher.Get();
        var devices = new List<ConnectedDevice>();
        foreach (var item in results.Cast<ManagementObject>())
        {
            using (item)
            {
                if (item["PNPDeviceID"] is string id)
                {
                    var deviceClass = item["PNPClass"] as string ?? "Unknown";
                    // For USB storage, the parent USB device is what an approval has to name (see ApprovedDevicesEnforcer).
                    var parent = deviceClass == "DiskDrive" ? DeviceList.Parent(id) : null;
                    devices.Add(new ConnectedDevice(id, item["Name"] as string ?? id, deviceClass, item["Manufacturer"] as string, parent));
                }
            }
        }

        return devices;
    }

    /// <summary>Property values of the first result, copied out before the WMI objects are released.</summary>
    /// <summary>
    /// Programs from the registry "Uninstall" keys that feed Windows "Installed apps": machine-wide (64- and
    /// 32-bit) and, for users whose profile is loaded, per-user installations. Updates and system components are skipped.
    /// </summary>
    public IReadOnlyList<InstalledSoftware> CollectSoftware()
    {
        const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        var result = new List<InstalledSoftware>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            Read(hklm.OpenSubKey(UninstallKey), "Machine", result);
        }

        using (var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default))
        {
            foreach (var sid in users.GetSubKeyNames().Where(n => n.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !n.EndsWith("_Classes", StringComparison.Ordinal)))
            {
                Read(users.OpenSubKey(sid + "\\" + UninstallKey), "User", result);
            }
        }

        return result
            .GroupBy(s => (s.Name.ToUpperInvariant(), s.Version, s.Scope))
            .Select(g => g.First())
            .ToList();
    }

    private static void Read(RegistryKey? uninstall, string scope, List<InstalledSoftware> into)
    {
        using (uninstall)
        {
            if (uninstall is null)
            {
                return;
            }

            foreach (var name in uninstall.GetSubKeyNames())
            {
                using var entry = uninstall.OpenSubKey(name);
                if (entry?.GetValue("DisplayName") is not string displayName || string.IsNullOrWhiteSpace(displayName) ||
                    entry.GetValue("SystemComponent") is 1 || entry.GetValue("ParentKeyName") is not null ||
                    entry.GetValue("ReleaseType") is "Update" or "Hotfix" or "Security Update")
                {
                    continue;
                }

                DateOnly? installed = entry.GetValue("InstallDate") is string date &&
                    DateOnly.TryParseExact(date, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) ? parsed : null;
                into.Add(new InstalledSoftware(displayName.Trim(), (entry.GetValue("DisplayVersion") as string)?.Trim(), (entry.GetValue("Publisher") as string)?.Trim(), installed, scope));
            }
        }
    }

    private static Dictionary<string, object?>? First(string query, string scope = @"root\cimv2")
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, query);
            using var results = searcher.Get();
            foreach (var item in results)
            {
                using (item)
                {
                    return item.Properties.Cast<PropertyData>().ToDictionary(p => p.Name, p => (object?)p.Value, StringComparer.OrdinalIgnoreCase);
                }
            }

            return null;
        }
        catch (ManagementException)
        {
            return null;
        }
    }

    private static long? SystemDiskGb()
    {
        var root = Path.GetPathRoot(Environment.SystemDirectory);
        return root is null ? null : new DriveInfo(root).TotalSize / (1024L * 1024 * 1024);
    }

    private static bool? TpmPresent()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftTpm", "SELECT IsEnabled_InitialValue FROM Win32_Tpm");
            using var results = searcher.Get();
            return results.Count > 0;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            return null; // Requires administrator rights; unknown otherwise.
        }
    }
}
