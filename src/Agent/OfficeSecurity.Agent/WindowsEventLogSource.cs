using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using OfficeSecurity.Agent.Core;

namespace OfficeSecurity.Agent;

/// <summary>Reads Windows event logs with the documented event log API (System.Diagnostics.Eventing.Reader).</summary>
internal sealed partial class WindowsEventLogSource : IWindowsEventSource
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";
    private Dictionary<string, string>? _devices;

    public long? LatestRecordId(string channel)
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName) { ReverseDirection = true });
            using var newest = reader.ReadEvent();
            return newest?.RecordId;
        }
        catch (EventLogNotFoundException)
        {
            return null;
        }
    }

    public IReadOnlyList<WindowsEventRecord> ReadAfter(string channel, IReadOnlyCollection<int> eventIds, long afterRecordId, int max)
    {
        var ids = string.Join(" or ", eventIds.Select(i => string.Create(CultureInfo.InvariantCulture, $"EventID={i}")));
        var query = new EventLogQuery(channel, PathType.LogName, string.Create(CultureInfo.InvariantCulture, $"*[System[({ids}) and EventRecordID > {afterRecordId}]]"));
        var result = new List<WindowsEventRecord>();
        try
        {
            using var reader = new EventLogReader(query);
            for (var record = reader.ReadEvent(); record is not null && result.Count < max; record = reader.ReadEvent())
            {
                using (record)
                {
                    result.Add(new WindowsEventRecord(channel, record.Id, record.RecordId ?? 0, record.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime()) : DateTimeOffset.UtcNow, Data(record)));
                }
            }
        }
        catch (EventLogNotFoundException)
        {
            // The log does not exist on this computer (e.g. Defender not installed).
        }

        return result;
    }

    private Dictionary<string, string> Data(EventRecord record)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var xml = XDocument.Parse(record.ToXml());
        foreach (var item in xml.Descendants(Ns + "Data"))
        {
            if ((string?)item.Attribute("Name") is { } name)
            {
                data[name] = DosPath(item.Value.Trim());
            }
        }

        return data;
    }

    /// <summary>"\Device\HarddiskVolume3\Users\x.exe" → "C:\Users\x.exe".</summary>
    private string DosPath(string value)
    {
        if (!value.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }

        _devices ??= DriveInfo.GetDrives().Select(d => d.Name[..2]).Distinct()
            .Select(letter => (letter, device: QueryDevice(letter)))
            .Where(x => x.device is not null)
            .ToDictionary(x => x.device!, x => x.letter, StringComparer.OrdinalIgnoreCase);
        foreach (var (device, letter) in _devices)
        {
            if (value.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return letter + value[device.Length..];
            }
        }

        return value;
    }

    private static string? QueryDevice(string driveLetter)
    {
        var buffer = new char[1024];
        var length = QueryDosDevice(driveLetter, buffer, buffer.Length);
        return length == 0 ? null : new string(buffer, 0, Array.IndexOf(buffer, '\0') is var end and >= 0 ? end : (int)length);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint QueryDosDevice(string deviceName, [Out] char[] targetPath, int max);
}
