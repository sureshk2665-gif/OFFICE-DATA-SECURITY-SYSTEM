using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace OfficeSecurity.Server.Infrastructure.Persistence;

public static class DatabaseInitializer
{
    /// <summary>Applies pending migrations and enables write-ahead logging (see ADR-0002).</summary>
    public static async Task InitializeAsync(ServerDbContext db, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken).ConfigureAwait(false);
    }

    public static string BuildConnectionString(string databaseFile) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = databaseFile,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            ForeignKeys = true,
            DefaultTimeout = 30,
        }.ToString();
}
