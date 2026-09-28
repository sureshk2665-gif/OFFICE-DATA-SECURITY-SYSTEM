using System.Globalization;
using System.Text.Json;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Core;

/// <summary>One record from a Windows event log, with its named data fields.</summary>
public sealed record WindowsEventRecord(string Channel, int EventId, long RecordId, DateTimeOffset TimeCreated, IReadOnlyDictionary<string, string> Data);

/// <summary>Reads Windows event logs (abstracted for tests).</summary>
public interface IWindowsEventSource
{
    /// <summary>The newest record id in the log, or null when the log is empty or does not exist.</summary>
    long? LatestRecordId(string channel);

    IReadOnlyList<WindowsEventRecord> ReadAfter(string channel, IReadOnlyCollection<int> eventIds, long afterRecordId, int max);
}

/// <summary>Collects security-relevant events for the current policy (called on every agent pass).</summary>
public interface IPolicyEventCollector
{
    void Collect(SecurityPolicyDocument policy);
}

/// <summary>
/// Turns Windows events that the policy asked for into security events for the server: programs blocked by
/// Application Control, Windows sign-ins, file access in protected folders and ransomware-protection blocks.
/// Only events that happen after a feature is switched on are reported.
/// </summary>
public sealed class WindowsEventForwarder(IWindowsEventSource source, PendingEventStore events, string bookmarkDirectory, TimeProvider clock) : IPolicyEventCollector
{
    public const string CodeIntegrityLog = "Microsoft-Windows-CodeIntegrity/Operational";
    public const string SecurityLog = "Security";
    public const string DefenderLog = "Microsoft-Windows-Windows Defender/Operational";
    public const int MaxPerPass = 200;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly Dictionary<string, DateTimeOffset> _recent = [];

    private string BookmarkPath => Path.Combine(bookmarkDirectory, "event-bookmarks.json");

    public void Collect(SecurityPolicyDocument policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var wanted = Subscriptions(policy);
        var bookmarks = LoadBookmarks();
        foreach (var gone in bookmarks.Keys.Where(k => !wanted.ContainsKey(k)).ToList())
        {
            bookmarks.Remove(gone);
        }

        foreach (var (channel, ids) in wanted)
        {
            if (!bookmarks.TryGetValue(channel, out var after))
            {
                // Just switched on: start from now, do not report history.
                bookmarks[channel] = source.LatestRecordId(channel) ?? 0;
                continue;
            }

            foreach (var record in source.ReadAfter(channel, ids, after, MaxPerPass))
            {
                bookmarks[channel] = Math.Max(bookmarks[channel], record.RecordId);
                Report(policy, record);
            }
        }

        SaveBookmarks(bookmarks);
        var cutoff = clock.GetUtcNow() - TimeSpan.FromHours(1);
        foreach (var key in _recent.Where(r => r.Value < cutoff).Select(r => r.Key).ToList())
        {
            _recent.Remove(key);
        }
    }

    private static Dictionary<string, int[]> Subscriptions(SecurityPolicyDocument policy)
    {
        var result = new Dictionary<string, int[]>();
        if (policy.ApplicationControl.Mode != EnforcementMode.Off)
        {
            result[CodeIntegrityLog] = [3076, 3077];
        }

        var security = new List<int>();
        if (policy.SignInAudit.RecordWindowsSignIns)
        {
            security.AddRange([4624, 4625, 4647]);
        }

        if (policy.FileProtection.ProtectedFolders.Any(f => f.AuditAccess))
        {
            security.Add(4663);
        }

        if (security.Count > 0)
        {
            result[SecurityLog] = [.. security];
        }

        if (policy.FileProtection.ProtectedFolders.Any(f => f.ControlledFolderAccess))
        {
            result[DefenderLog] = [1123, 1124];
        }

        return result;
    }

    private void Report(SecurityPolicyDocument policy, WindowsEventRecord e)
    {
        string V(string name) => e.Data.TryGetValue(name, out var v) ? v : string.Empty;
        switch (e.Channel, e.EventId)
        {
            case (CodeIntegrityLog, 3076 or 3077):
                if (!e.Data.Values.Any(v => v.Contains(AppControlEnforcer.PolicyName, StringComparison.OrdinalIgnoreCase)))
                {
                    return; // Another policy (e.g. Microsoft's vulnerable driver blocklist).
                }

                var file = V("File Name");
                if (Fresh($"app|{e.EventId}|{file}", TimeSpan.FromHours(1)))
                {
                    events.Enqueue(SecurityEventType.UnauthorizedApplicationBlocked, e.EventId == 3077 ? EventSeverities.Warning : EventSeverities.Information,
                        (e.EventId == 3077 ? "Blocked by Application Control: " : "Audit mode — would be blocked by Application Control: ") + $"{file} (started by {V("Process Name")})");
                }

                break;

            case (SecurityLog, 4624) when IsPerson(V("TargetUserSid"), V("TargetUserName")) && LogonKind(V("LogonType")) is { } how:
                if (Fresh($"logon|{V("TargetUserSid")}|{V("LogonType")}", TimeSpan.FromMinutes(1)))
                {
                    events.Enqueue(SecurityEventType.SuccessfulLogin, EventSeverities.Information, $@"{V("TargetDomainName")}\{V("TargetUserName")} signed in to Windows ({how}).");
                }

                break;

            case (SecurityLog, 4625) when LogonKind(V("LogonType")) is { } how:
                events.Enqueue(SecurityEventType.FailedLogin, EventSeverities.Warning,
                    $@"Failed Windows sign-in for {V("TargetDomainName")}\{V("TargetUserName")} ({how}): {FailureReason(V("SubStatus"), V("Status"))}.");
                break;

            case (SecurityLog, 4647) when IsPerson(V("TargetUserSid"), V("TargetUserName")):
                events.Enqueue(SecurityEventType.Logout, EventSeverities.Information, $@"{V("TargetDomainName")}\{V("TargetUserName")} signed out of Windows.");
                break;

            case (SecurityLog, 4663) when IsPerson(V("SubjectUserSid"), V("SubjectUserName")):
                var path = V("ObjectName");
                var folders = policy.FileProtection.ProtectedFolders.Where(f => f.AuditAccess).Select(f => f.Path.TrimEnd('\\'));
                if (!folders.Any(f => path.Equals(f, StringComparison.OrdinalIgnoreCase) || path.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                var verb = Access(V("AccessMask"));
                if (verb is not null && Fresh($"file|{V("SubjectUserSid")}|{path}|{verb}", TimeSpan.FromMinutes(10)))
                {
                    events.Enqueue(SecurityEventType.ProtectedFileAccess, EventSeverities.Information,
                        $@"{V("SubjectDomainName")}\{V("SubjectUserName")} {verb} {path} (program: {V("ProcessName")}).");
                }

                break;

            case (DefenderLog, 1123 or 1124):
                events.Enqueue(SecurityEventType.PolicyViolation, e.EventId == 1123 ? EventSeverities.Warning : EventSeverities.Information,
                    (e.EventId == 1123 ? "Ransomware protection blocked " : "Ransomware protection (audit) would block ") + $"{V("Process Name")} from changing {V("Path")} (user {V("User")}).");
                break;
        }
    }

    /// <summary>Real people: local or domain accounts, not computer accounts or Windows' own services.</summary>
    private static bool IsPerson(string sid, string name) =>
        sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !name.EndsWith('$');

    private static string? LogonKind(string logonType) => logonType switch
    {
        "2" => "at the computer",
        "7" => "unlocked the computer",
        "10" => "remote desktop",
        "11" => "with saved credentials, offline",
        _ => null,
    };

    private static string FailureReason(string subStatus, string status) => (subStatus is { Length: > 0 } and not "0x0" ? subStatus : status).ToUpperInvariant() switch
    {
        "0XC000006A" => "wrong password",
        "0XC0000064" => "unknown user name",
        "0XC0000234" => "account locked out",
        "0XC0000072" => "account disabled",
        "0XC000006F" => "outside allowed sign-in hours",
        "0XC0000070" => "not allowed on this computer",
        "0XC0000071" => "password expired",
        "0XC0000193" => "account expired",
        var code => "Windows code " + code,
    };

    private static string? Access(string mask)
    {
        if (!int.TryParse(mask.Replace("0x", string.Empty, StringComparison.OrdinalIgnoreCase), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var m))
        {
            return null;
        }

        return (m & 0x10000) != 0 ? "deleted" : (m & 0x6) != 0 ? "changed" : (m & 0x1) != 0 ? "opened" : null;
    }

    private bool Fresh(string key, TimeSpan window)
    {
        var now = clock.GetUtcNow();
        if (_recent.TryGetValue(key, out var last) && now - last < window)
        {
            return false;
        }

        _recent[key] = now;
        return true;
    }

    private Dictionary<string, long> LoadBookmarks()
    {
        try
        {
            return File.Exists(BookmarkPath) ? JsonSerializer.Deserialize<Dictionary<string, long>>(File.ReadAllText(BookmarkPath)) ?? [] : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private void SaveBookmarks(Dictionary<string, long> bookmarks)
    {
        Directory.CreateDirectory(bookmarkDirectory);
        File.WriteAllText(BookmarkPath + ".tmp", JsonSerializer.Serialize(bookmarks, Json));
        File.Move(BookmarkPath + ".tmp", BookmarkPath, overwrite: true);
    }
}
