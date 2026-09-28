using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent;

/// <summary>Windows' device list through the documented SetupAPI / Configuration Manager functions.</summary>
internal static partial class DeviceList
{
    private const uint DigcfPresent = 0x2;
    private const uint DigcfAllClasses = 0x4;
    private const uint SpdrpCompatibleIds = 0x2;
    private const int CrSuccess = 0;
    private const uint DnHasProblem = 0x400;
    private const uint ProblemDisabled = 22; // CM_PROB_DISABLED

    public sealed record Node(string InstanceId, bool IsPresent, IReadOnlyList<string> CompatibleIds, bool Disabled);

    /// <summary>All device nodes (optionally of one setup class), including ones not connected now.</summary>
    public static List<Node> All(Guid? setupClass = null, bool presentOnly = false)
    {
        var flags = (setupClass is null ? DigcfAllClasses : 0) | (presentOnly ? DigcfPresent : 0);
        var set = setupClass is { } classGuid
            ? SetupDiGetClassDevsForClass(in classGuid, null, IntPtr.Zero, flags)
            : SetupDiGetClassDevsW(IntPtr.Zero, null, IntPtr.Zero, flags);
        if (set == new IntPtr(-1))
        {
            throw new InvalidOperationException($"Could not read the Windows device list (error {Marshal.GetLastPInvokeError()}).");
        }

        var result = new List<Node>();
        try
        {
            var data = new SpDevinfoData { CbSize = (uint)Marshal.SizeOf<SpDevinfoData>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(set, i, ref data); i++)
            {
                var id = InstanceId(set, ref data);
                if (id is null)
                {
                    continue;
                }

                var present = CM_Get_DevNode_Status(out var status, out var problem, data.DevInst, 0) == CrSuccess;
                result.Add(new Node(id, present, CompatibleIds(set, ref data), present && (status & DnHasProblem) != 0 && problem == ProblemDisabled));
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(set);
        }

        return result;
    }

    /// <summary>Uninstalls a device node and its children (DiUninstallDevice, as Device Manager does).</summary>
    public static void Uninstall(string instanceId)
    {
        var set = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
        try
        {
            var data = new SpDevinfoData { CbSize = (uint)Marshal.SizeOf<SpDevinfoData>() };
            if (!SetupDiOpenDeviceInfoW(set, instanceId, IntPtr.Zero, 0, ref data))
            {
                throw new InvalidOperationException($"Device {instanceId} was not found (error {Marshal.GetLastPInvokeError()}).");
            }

            if (!DiUninstallDevice(IntPtr.Zero, set, ref data, 0, out _))
            {
                throw new InvalidOperationException($"Device {instanceId} could not be removed (error {Marshal.GetLastPInvokeError()}).");
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(set);
        }
    }

    /// <summary>The parent device's instance ID (e.g. the USB device a USB disk belongs to).</summary>
    public static string? Parent(string instanceId)
    {
        if (CM_Locate_DevNodeW(out var node, instanceId, 1 /* CM_LOCATE_DEVNODE_PHANTOM */) != CrSuccess
            || CM_Get_Parent(out var parent, node, 0) != CrSuccess)
        {
            return null;
        }

        var buffer = new char[400];
        return CM_Get_Device_IDW(parent, buffer, (uint)buffer.Length, 0) == CrSuccess ? new string(buffer, 0, Array.IndexOf(buffer, '\0') is var e and >= 0 ? e : buffer.Length) : null;
    }

    private static string? InstanceId(IntPtr set, ref SpDevinfoData data)
    {
        var buffer = new char[400];
        return SetupDiGetDeviceInstanceIdW(set, ref data, buffer, buffer.Length, out var length) ? new string(buffer, 0, Math.Max(0, length - 1)) : null;
    }

    private static List<string> CompatibleIds(IntPtr set, ref SpDevinfoData data)
    {
        var buffer = new byte[4096];
        if (!SetupDiGetDeviceRegistryPropertyW(set, ref data, SpdrpCompatibleIds, out _, buffer, (uint)buffer.Length, out var size))
        {
            return [];
        }

        return Encoding.Unicode.GetString(buffer, 0, (int)size).Split('\0', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SpDevinfoData
    {
        public uint CbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [LibraryImport("setupapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr SetupDiGetClassDevsW(IntPtr classGuid, string? enumerator, IntPtr parent, uint flags);

    [LibraryImport("setupapi.dll", EntryPoint = "SetupDiGetClassDevsW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr SetupDiGetClassDevsForClass(in Guid classGuid, string? enumerator, IntPtr parent, uint flags);

    [LibraryImport("setupapi.dll", SetLastError = true)]
    private static partial IntPtr SetupDiCreateDeviceInfoList(IntPtr classGuid, IntPtr parent);

    [LibraryImport("setupapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetupDiOpenDeviceInfoW(IntPtr set, string instanceId, IntPtr parent, uint flags, ref SpDevinfoData data);

    [LibraryImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref SpDevinfoData data);

    [LibraryImport("setupapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetupDiGetDeviceInstanceIdW(IntPtr set, ref SpDevinfoData data, [Out] char[] buffer, int size, out int required);

    [LibraryImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, ref SpDevinfoData data, uint property, out uint type, [Out] byte[] buffer, uint size, out uint required);

    [LibraryImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetupDiDestroyDeviceInfoList(IntPtr set);

    [LibraryImport("newdev.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DiUninstallDevice(IntPtr window, IntPtr set, ref SpDevinfoData data, uint flags, [MarshalAs(UnmanagedType.Bool)] out bool needReboot);

    [LibraryImport("cfgmgr32.dll")]
    private static partial int CM_Get_DevNode_Status(out uint status, out uint problem, uint devInst, uint flags);

    [LibraryImport("cfgmgr32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int CM_Locate_DevNodeW(out uint devInst, string deviceId, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial int CM_Get_Parent(out uint parent, uint devInst, uint flags);

    [LibraryImport("cfgmgr32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int CM_Get_Device_IDW(uint devInst, [Out] char[] buffer, uint length, uint flags);
}

/// <summary>USB mass-storage device nodes (compatible ID USB\Class_08), connected or not.</summary>
internal sealed class WindowsUsbStorageDevices : IUsbStorageDevices
{
    public IReadOnlyList<StorageDeviceNode> List() =>
        DeviceList.All()
            .Where(n => n.CompatibleIds.Any(c => c.StartsWith(ApprovedDevicesEnforcer.UsbMassStorage, StringComparison.OrdinalIgnoreCase)))
            .Select(n => new StorageDeviceNode(n.InstanceId, n.IsPresent))
            .ToList();

    public void Remove(string instanceId) => DeviceList.Uninstall(instanceId);
}

/// <summary>Bluetooth adapters: present devices of the Bluetooth setup class that are not paired devices or services.</summary>
internal sealed class WindowsBluetooth : IBluetoothRadios
{
    private static readonly Guid BluetoothClass = new("e0cbf06c-cd8b-4647-bb8a-263b43f0f974");

    public IReadOnlyList<(string InstanceId, bool Disabled)> Radios() =>
        DeviceList.All(BluetoothClass, presentOnly: true)
            .Where(n => !n.InstanceId.StartsWith("BTH", StringComparison.OrdinalIgnoreCase) && !n.InstanceId.StartsWith("SWD", StringComparison.OrdinalIgnoreCase))
            .Select(n => (n.InstanceId, n.Disabled))
            .ToList();

    public void Disable(string instanceId) => PnpUtil("/disable-device", instanceId);

    public void Enable(string instanceId) => PnpUtil("/enable-device", instanceId);

    private static void PnpUtil(string action, string instanceId)
    {
        var (code, output) = Tool.Run(Tool.System32("pnputil.exe"), action, instanceId);
        if (code is not 0 and not 3010)
        {
            throw new InvalidOperationException($"pnputil {action} failed ({code}): {output.Trim()}");
        }
    }
}

/// <summary>
/// Wi-Fi filters: changed with "netsh wlan add/delete filter" (a Windows tool), read back with the Native Wifi API
/// (WlanGetFilterList), which does not depend on the Windows display language.
/// </summary>
internal sealed partial class WindowsWifi : IWifi
{
    private const int FilterUserPermit = 2;
    private const int FilterUserDeny = 3;

    public bool Available()
    {
        if (WlanOpenHandle(2, IntPtr.Zero, out _, out var client) != 0)
        {
            return false;
        }

        try
        {
            if (WlanEnumInterfaces(client, IntPtr.Zero, out var list) != 0)
            {
                return false;
            }

            var count = Marshal.ReadInt32(list);
            WlanFreeMemory(list);
            return count > 0;
        }
        finally
        {
            _ = WlanCloseHandle(client, IntPtr.Zero);
        }
    }

    public string? ConnectedNetwork()
    {
        if (WlanOpenHandle(2, IntPtr.Zero, out _, out var client) != 0)
        {
            return null;
        }

        try
        {
            if (WlanEnumInterfaces(client, IntPtr.Zero, out var list) != 0)
            {
                return null;
            }

            try
            {
                var count = Marshal.ReadInt32(list);
                const int InterfaceInfoSize = 16 + 512 + 4; // GUID, WCHAR[256], state
                for (var i = 0; i < count; i++)
                {
                    var guid = Marshal.PtrToStructure<Guid>(list + 8 + (i * InterfaceInfoSize));
                    if (WlanQueryInterface(client, in guid, 7 /* current_connection */, IntPtr.Zero, out _, out var data, out _) != 0)
                    {
                        continue;
                    }

                    try
                    {
                        // WLAN_CONNECTION_ATTRIBUTES: state, mode, profile name (WCHAR[256]), then DOT11_SSID.
                        if (Marshal.ReadInt32(data) == 1 /* connected */)
                        {
                            return Ssid(data + 8 + 512);
                        }
                    }
                    finally
                    {
                        WlanFreeMemory(data);
                    }
                }
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }
        finally
        {
            _ = WlanCloseHandle(client, IntPtr.Zero);
        }

        return null;
    }

    public (IReadOnlyList<string> Allowed, bool DenyAll) Filters()
    {
        if (WlanOpenHandle(2, IntPtr.Zero, out _, out var client) != 0)
        {
            return ([], false);
        }

        try
        {
            var allowed = List(client, FilterUserPermit).Where(n => n.Ssid.Length > 0).Select(n => n.Ssid).ToList();
            var deny = List(client, FilterUserDeny);
            return (allowed, deny.Any(n => n.Ssid.Length == 0));
        }
        finally
        {
            _ = WlanCloseHandle(client, IntPtr.Zero);
        }
    }

    public void Allow(string ssid) => Netsh("add", "permission=allow", $"ssid={ssid}", "networktype=infrastructure");

    public void RemoveAllow(string ssid) => Netsh("delete", "permission=allow", $"ssid={ssid}", "networktype=infrastructure");

    public void SetDenyAll(bool deny)
    {
        foreach (var type in new[] { "infrastructure", "adhoc" })
        {
            Netsh(deny ? "add" : "delete", "permission=denyall", $"networktype={type}");
        }
    }

    private static void Netsh(string verb, params string[] arguments)
    {
        var (code, output) = Tool.Run(Tool.System32("netsh.exe"), ["wlan", verb, "filter", .. arguments]);
        if (code != 0)
        {
            throw new InvalidOperationException($"netsh wlan {verb} filter failed ({code}): {output.Trim()}");
        }
    }

    private static List<(string Ssid, int BssType)> List(IntPtr client, int type)
    {
        var result = new List<(string, int)>();
        if (WlanGetFilterList(client, type, IntPtr.Zero, out var list) != 0 || list == IntPtr.Zero)
        {
            return result;
        }

        try
        {
            var count = Marshal.ReadInt32(list);
            const int NetworkSize = 4 + 32 + 4; // DOT11_SSID (length + 32 bytes) + DOT11_BSS_TYPE
            for (var i = 0; i < count; i++)
            {
                var item = list + 8 + (i * NetworkSize);
                result.Add((Ssid(item), Marshal.ReadInt32(item + 36)));
            }
        }
        finally
        {
            WlanFreeMemory(list);
        }

        return result;
    }

    private static string Ssid(IntPtr dot11Ssid)
    {
        var length = Math.Clamp(Marshal.ReadInt32(dot11Ssid), 0, 32);
        var bytes = new byte[length];
        Marshal.Copy(dot11Ssid + 4, bytes, 0, length);
        return Encoding.UTF8.GetString(bytes);
    }

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr client);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanCloseHandle(IntPtr client, IntPtr reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanEnumInterfaces(IntPtr client, IntPtr reserved, out IntPtr interfaceList);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanQueryInterface(IntPtr client, in Guid interfaceGuid, int opCode, IntPtr reserved, out uint dataSize, out IntPtr data, out int valueType);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanGetFilterList(IntPtr client, int filterListType, IntPtr reserved, out IntPtr networkList);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(IntPtr memory);
}

/// <summary>BitLocker recovery passwords of this computer's drives (Win32_EncryptableVolume, SYSTEM only).</summary>
internal static class WindowsRecoveryKeys
{
    private const string Namespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";

    public static IReadOnlyList<RecoveryKeyReport> Read()
    {
        var result = new List<RecoveryKeyReport>();
        try
        {
            using var searcher = new ManagementObjectSearcher(Namespace, "SELECT * FROM Win32_EncryptableVolume");
            foreach (ManagementObject volume in searcher.Get())
            {
                using (volume)
                {
                    if (volume["DriveLetter"] is not string drive)
                    {
                        continue;
                    }

                    using var protectors = volume.InvokeMethod("GetKeyProtectors", volume.GetMethodParameters("GetKeyProtectors") is { } p ? Set(p, "KeyProtectorType", 3u) : null, null);
                    if (protectors?["VolumeKeyProtectorID"] is not string[] ids)
                    {
                        continue;
                    }

                    foreach (var id in ids)
                    {
                        var input = volume.GetMethodParameters("GetKeyProtectorNumericalPassword");
                        input["VolumeKeyProtectorID"] = id;
                        using var output = volume.InvokeMethod("GetKeyProtectorNumericalPassword", input, null);
                        if (output?["NumericalPassword"] is string password && password.Length > 0)
                        {
                            result.Add(new RecoveryKeyReport(drive, id, password));
                        }
                    }
                }
            }
        }
        catch (ManagementException)
        {
            // BitLocker not available on this computer.
        }

        return result;
    }

    private static ManagementBaseObject Set(ManagementBaseObject parameters, string name, object value)
    {
        parameters[name] = value;
        return parameters;
    }
}
