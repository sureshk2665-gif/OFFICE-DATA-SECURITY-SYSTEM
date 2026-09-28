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

    DbSet<Computer> Computers { get; }

    DbSet<EnrollmentCode> EnrollmentCodes { get; }

    DbSet<DeviceInventoryItem> Devices { get; }

    DbSet<SecurityEvent> SecurityEvents { get; }

    DbSet<PolicyDefinition> Policies { get; }

    DbSet<StaffComputerAssignment> StaffAssignments { get; }

    DbSet<SoftwareInventoryItem> InstalledSoftware { get; }

    DbSet<ApprovedSoftware> ApprovedSoftware { get; }

    DbSet<SoftwarePackage> SoftwarePackages { get; }

    DbSet<SoftwareRequest> SoftwareRequests { get; }

    DbSet<DeploymentJob> DeploymentJobs { get; }

    DbSet<ControlExemption> Exemptions { get; }

    DbSet<BitLockerRecoveryKey> RecoveryKeys { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
