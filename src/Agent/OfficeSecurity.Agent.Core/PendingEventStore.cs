using System.Globalization;
using Microsoft.Data.Sqlite;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Core;

/// <summary>
/// Security events waiting to be sent to the server. Stored in a local SQLite file so nothing is lost
/// while the network or server is unavailable, or across restarts.
/// </summary>
public sealed class PendingEventStore
{
    /// <summary>Beyond this many unsent events the oldest are discarded (about months of normal activity).</summary>
    public const int MaxPendingEvents = 100_000;

    private readonly string _connectionString;
    private readonly TimeProvider _clock;
    private readonly int _maxPending;

    public PendingEventStore(AgentPaths paths, TimeProvider clock, int maxPending = MaxPendingEvents)
    {
        ArgumentNullException.ThrowIfNull(paths);
        _clock = clock;
        _maxPending = maxPending;
        Directory.CreateDirectory(paths.DataDirectory);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = paths.EventQueueFile, Pooling = false }.ToString();
        Execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                type INTEGER NOT NULL,
                severity TEXT NOT NULL,
                occurred_ticks INTEGER NOT NULL,
                details TEXT NULL,
                uploaded INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS ix_events_pending ON events(uploaded, occurred_ticks);
            """);
    }

    public void Enqueue(SecurityEventType type, string severity, string? details)
    {
        Execute("INSERT INTO events (id, type, severity, occurred_ticks, details) VALUES ($id, $type, $severity, $ticks, $details)",
            ("$id", Guid.NewGuid().ToString("D")), ("$type", (int)type), ("$severity", severity), ("$ticks", _clock.GetUtcNow().UtcTicks), ("$details", details));
        Execute($"""
            DELETE FROM events WHERE id IN (
                SELECT id FROM events WHERE uploaded = 0 ORDER BY occurred_ticks DESC, rowid DESC LIMIT -1 OFFSET {_maxPending.ToString(CultureInfo.InvariantCulture)});
            """);
    }

    public int PendingCount()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM events WHERE uploaded = 0";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    public IReadOnlyList<AgentEvent> PeekPending(int max)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, type, severity, occurred_ticks, details FROM events WHERE uploaded = 0 ORDER BY occurred_ticks, rowid LIMIT $max";
        command.Parameters.AddWithValue("$max", max);
        using var reader = command.ExecuteReader();
        var events = new List<AgentEvent>();
        while (reader.Read())
        {
            events.Add(new AgentEvent(
                Guid.Parse(reader.GetString(0)),
                (SecurityEventType)reader.GetInt32(1),
                reader.GetString(2),
                new DateTimeOffset(reader.GetInt64(3), TimeSpan.Zero),
                reader.IsDBNull(4) ? null : reader.GetString(4)));
        }

        return events;
    }

    public void MarkUploaded(IEnumerable<Guid> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        foreach (var id in ids)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "UPDATE events SET uploaded = 1 WHERE id = $id";
            command.Parameters.AddWithValue("$id", id.ToString("D"));
            command.ExecuteNonQuery();
        }

        // Keep sent events for a week for local troubleshooting, then remove them.
        using (var prune = connection.CreateCommand())
        {
            prune.Transaction = transaction;
            prune.CommandText = "DELETE FROM events WHERE uploaded = 1 AND occurred_ticks < $cutoff";
            prune.Parameters.AddWithValue("$cutoff", _clock.GetUtcNow().AddDays(-7).UtcTicks);
            prune.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private void Execute(string sql, params (string Name, object? Value)[] parameters)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        command.ExecuteNonQuery();
    }
}
