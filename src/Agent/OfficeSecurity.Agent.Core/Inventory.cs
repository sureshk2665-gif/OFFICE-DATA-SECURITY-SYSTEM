using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Core;

/// <summary>Collects computer and device information. The Windows implementation uses WMI and the registry.</summary>
public interface IInventoryCollector
{
    HardwareInventory CollectHardware();

    /// <summary>Removable storage, phones/cameras (MTP/PTP) and Bluetooth devices currently present.</summary>
    IReadOnlyList<ConnectedDevice> CollectDevices();
}

/// <summary>Minimal portable inventory (development and tests on non-Windows systems).</summary>
public sealed class BasicInventoryCollector : IInventoryCollector
{
    public HardwareInventory CollectHardware() => new(
        Environment.MachineName,
        System.Runtime.InteropServices.RuntimeInformation.OSDescription,
        Environment.OSVersion.Version.ToString(),
        null, null, null, null, null, null,
        null, null, null, null, null);

    public IReadOnlyList<ConnectedDevice> CollectDevices() => [];
}
