using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace OfficeSecurity.Server.Infrastructure.Persistence;

/// <summary>Used only by the "dotnet ef" tool to create migrations.</summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ServerDbContext>
{
    public ServerDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<ServerDbContext>().UseSqlite("Data Source=design-time.db").Options);
}
