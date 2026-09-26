namespace OfficeSecurity.Server.Application.Services;

/// <summary>Online/offline rule shared by every screen and report.</summary>
public static class ComputerPresence
{
    /// <summary>A computer is online if it reported within three heartbeat intervals (minimum three minutes).</summary>
    public static bool IsOnline(DateTimeOffset? lastSeenUtc, int heartbeatIntervalSeconds, DateTimeOffset nowUtc) =>
        lastSeenUtc is { } seen && nowUtc - seen <= TimeSpan.FromSeconds(Math.Max(180, heartbeatIntervalSeconds * 3));
}
