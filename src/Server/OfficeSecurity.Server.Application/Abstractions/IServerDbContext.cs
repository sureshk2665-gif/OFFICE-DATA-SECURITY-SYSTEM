using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Abstractions;

public interface IServerDbContext
{
    DbSet<AdminAccount> Admins { get; }

    DbSet<StaffAccount> Staff { get; }

    DbSet<AccountSetupCode> SetupCodes { get; }

    DbSet<Session> Sessions { get; }

    DbSet<AuditEntry> AuditEntries { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
