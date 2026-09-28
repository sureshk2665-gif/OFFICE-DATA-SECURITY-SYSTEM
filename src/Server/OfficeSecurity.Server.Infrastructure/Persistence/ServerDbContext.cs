using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Infrastructure.Persistence;

public sealed class ServerDbContext(DbContextOptions<ServerDbContext> options) : DbContext(options), IServerDbContext
{
    public DbSet<AdminAccount> Admins => Set<AdminAccount>();

    public DbSet<StaffAccount> Staff => Set<StaffAccount>();

    public DbSet<AccountSetupCode> SetupCodes => Set<AccountSetupCode>();

    public DbSet<Session> Sessions => Set<Session>();

    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    public DbSet<Computer> Computers => Set<Computer>();

    public DbSet<EnrollmentCode> EnrollmentCodes => Set<EnrollmentCode>();

    public DbSet<DeviceInventoryItem> Devices => Set<DeviceInventoryItem>();

    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();

    public DbSet<PolicyDefinition> Policies => Set<PolicyDefinition>();

    public DbSet<StaffComputerAssignment> StaffAssignments => Set<StaffComputerAssignment>();

    public DbSet<SoftwareInventoryItem> InstalledSoftware => Set<SoftwareInventoryItem>();

    public DbSet<ApprovedSoftware> ApprovedSoftware => Set<ApprovedSoftware>();

    public DbSet<SoftwarePackage> SoftwarePackages => Set<SoftwarePackage>();

    public DbSet<SoftwareRequest> SoftwareRequests => Set<SoftwareRequest>();

    public DbSet<DeploymentJob> DeploymentJobs => Set<DeploymentJob>();

    public DbSet<ControlExemption> Exemptions => Set<ControlExemption>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        ArgumentNullException.ThrowIfNull(configurationBuilder);

        // SQLite has no native date/time type. Timestamps are stored as exact UTC ticks: sortable, comparable,
        // and lossless (the audit hash chain depends on reading back exactly what was written).
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<UtcTicksConverter>();

        // Enums are stored as text so the database stays readable and values never shift.
        configurationBuilder.Properties<AdminRole>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<AccountStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<PrincipalType>().HaveConversion<string>().HaveMaxLength(16);
        configurationBuilder.Properties<AuditActorType>().HaveConversion<string>().HaveMaxLength(16);
        configurationBuilder.Properties<AuditOutcome>().HaveConversion<string>().HaveMaxLength(16);
        configurationBuilder.Properties<ComputerStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<SoftwareRequestStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<DeploymentStatus>().HaveConversion<string>().HaveMaxLength(32);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<AdminAccount>(e =>
        {
            e.ToTable("admin_accounts");
            e.HasKey(a => a.Id);
            e.Property(a => a.Username).HasMaxLength(64).IsRequired();
            e.Property(a => a.NormalizedUsername).HasMaxLength(64).IsRequired();
            e.HasIndex(a => a.NormalizedUsername).IsUnique();
            e.Property(a => a.DisplayName).HasMaxLength(100).IsRequired();
            e.Property(a => a.PasswordHash).HasMaxLength(256);
            e.Property(a => a.TotpSecretProtected).HasMaxLength(1024);
        });

        modelBuilder.Entity<StaffAccount>(e =>
        {
            e.ToTable("staff_accounts");
            e.HasKey(s => s.Id);
            e.Property(s => s.EmployeeCode).HasMaxLength(32).IsRequired();
            e.Property(s => s.NormalizedEmployeeCode).HasMaxLength(32).IsRequired();
            e.HasIndex(s => s.NormalizedEmployeeCode).IsUnique();
            e.Property(s => s.DisplayName).HasMaxLength(100).IsRequired();
            e.Property(s => s.Department).HasMaxLength(100);
            e.Property(s => s.PasswordHash).HasMaxLength(256);
            e.HasIndex(s => s.Status);
            e.HasIndex(s => s.DisplayName);
        });

        modelBuilder.Entity<AccountSetupCode>(e =>
        {
            e.ToTable("account_setup_codes");
            e.HasKey(c => c.Id);
            e.Property(c => c.CodeHash).HasMaxLength(64).IsRequired();
            e.HasIndex(c => new { c.AccountType, c.AccountId });
            e.HasIndex(c => c.CodeHash);
        });

        modelBuilder.Entity<Session>(e =>
        {
            e.ToTable("sessions");
            e.HasKey(s => s.Id);
            e.Property(s => s.TokenHash).HasMaxLength(64).IsRequired();
            e.HasIndex(s => s.TokenHash).IsUnique();
            e.HasIndex(s => new { s.PrincipalType, s.PrincipalId });
            e.Property(s => s.EndReason).HasMaxLength(64);
            e.Property(s => s.SourceIp).HasMaxLength(64);
        });

        modelBuilder.Entity<AuditEntry>(e =>
        {
            e.ToTable("audit_log");
            e.HasKey(a => a.Id);
            e.Property(a => a.Id).ValueGeneratedOnAdd();
            e.Property(a => a.ActorName).HasMaxLength(100);
            e.Property(a => a.Action).HasMaxLength(100).IsRequired();
            e.Property(a => a.TargetType).HasMaxLength(50);
            e.Property(a => a.TargetId).HasMaxLength(100);
            e.Property(a => a.SourceIp).HasMaxLength(64);
            e.Property(a => a.Details).HasMaxLength(2000);
            e.Property(a => a.PreviousHash).HasMaxLength(64).IsRequired();
            e.Property(a => a.Hash).HasMaxLength(64).IsRequired();
            e.HasIndex(a => a.OccurredAtUtc);
            e.HasIndex(a => a.Action);
        });

        modelBuilder.Entity<Computer>(e =>
        {
            e.ToTable("computers");
            e.HasKey(c => c.Id);
            e.Property(c => c.Hostname).HasMaxLength(64).IsRequired();
            e.Property(c => c.CertificateRequestPem).HasMaxLength(4000);
            e.Property(c => c.PollTokenHash).HasMaxLength(64);
            e.Property(c => c.CertificatePem).HasMaxLength(4000);
            e.Property(c => c.CertificateThumbprint).HasMaxLength(64);
            e.HasIndex(c => c.CertificateThumbprint).IsUnique();
            e.Property(c => c.LastSeenIp).HasMaxLength(64);
            e.Property(c => c.AgentVersion).HasMaxLength(64);
            e.Property(c => c.HardwareJson).HasMaxLength(8000);
            e.Property(c => c.OsName).HasMaxLength(128);
            e.Property(c => c.OsEdition).HasMaxLength(64);
            e.Property(c => c.ControlStatusJson).HasMaxLength(16000);
            e.HasIndex(c => c.Status);
            e.HasIndex(c => c.Hostname);
            e.HasOne<PolicyDefinition>().WithMany().HasForeignKey(c => c.PolicyId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<EnrollmentCode>(e =>
        {
            e.ToTable("enrollment_codes");
            e.HasKey(c => c.Id);
            e.Property(c => c.CodeHash).HasMaxLength(64).IsRequired();
            e.HasIndex(c => c.CodeHash).IsUnique();
        });

        modelBuilder.Entity<DeviceInventoryItem>(e =>
        {
            e.ToTable("device_inventory");
            e.HasKey(d => d.Id);
            e.Property(d => d.Id).ValueGeneratedOnAdd();
            e.Property(d => d.InstanceId).HasMaxLength(400).IsRequired();
            e.Property(d => d.Name).HasMaxLength(256).IsRequired();
            e.Property(d => d.DeviceClass).HasMaxLength(64).IsRequired();
            e.Property(d => d.Manufacturer).HasMaxLength(256);
            e.HasIndex(d => new { d.ComputerId, d.InstanceId }).IsUnique();
            e.HasOne<Computer>().WithMany().HasForeignKey(d => d.ComputerId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SecurityEvent>(e =>
        {
            e.ToTable("security_events");
            e.HasKey(v => v.Id);
            e.Property(v => v.Id).ValueGeneratedOnAdd();
            e.Property(v => v.EventType).HasMaxLength(64).IsRequired();
            e.Property(v => v.Severity).HasMaxLength(16).IsRequired();
            e.Property(v => v.Details).HasMaxLength(2000);
            e.HasIndex(v => new { v.ComputerId, v.EventId }).IsUnique();
            e.HasIndex(v => new { v.ComputerId, v.OccurredAtUtc });
            e.HasIndex(v => new { v.EventType, v.OccurredAtUtc });
            e.HasOne<Computer>().WithMany().HasForeignKey(v => v.ComputerId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<PolicyDefinition>(e =>
        {
            e.ToTable("policies");
            e.HasKey(p => p.Id);
            e.Property(p => p.Name).HasMaxLength(100).IsRequired();
            e.HasIndex(p => p.Name).IsUnique();
            e.Property(p => p.Description).HasMaxLength(500);
            e.Property(p => p.SettingsJson).HasMaxLength(64000).IsRequired();
        });

        modelBuilder.Entity<SoftwareInventoryItem>(e =>
        {
            e.ToTable("software_inventory");
            e.HasKey(i => i.Id);
            e.Property(i => i.Id).ValueGeneratedOnAdd();
            e.Property(i => i.Name).HasMaxLength(256).IsRequired();
            e.Property(i => i.Version).HasMaxLength(64).IsRequired();
            e.Property(i => i.Publisher).HasMaxLength(256);
            e.Property(i => i.Scope).HasMaxLength(16).IsRequired();
            e.HasIndex(i => new { i.ComputerId, i.Name, i.Version, i.Scope }).IsUnique();
            e.HasIndex(i => i.Name);
            e.HasOne<Computer>().WithMany().HasForeignKey(i => i.ComputerId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ApprovedSoftware>(e =>
        {
            e.ToTable("approved_software");
            e.HasKey(a => a.Id);
            e.Property(a => a.Name).HasMaxLength(256).IsRequired();
            e.Property(a => a.Publisher).HasMaxLength(256);
            e.Property(a => a.Notes).HasMaxLength(1000);
            e.HasIndex(a => a.Name).IsUnique();
        });

        modelBuilder.Entity<SoftwarePackage>(e =>
        {
            e.ToTable("software_packages");
            e.HasKey(p => p.Id);
            e.Property(p => p.FileName).HasMaxLength(260).IsRequired();
            e.Property(p => p.Sha256).HasMaxLength(64).IsRequired();
            e.Property(p => p.InstallerType).HasMaxLength(8).IsRequired();
            e.Property(p => p.SilentArguments).HasMaxLength(512);
            e.Property(p => p.SignerSubject).HasMaxLength(512);
            e.HasOne<ApprovedSoftware>().WithMany().HasForeignKey(p => p.ApprovedSoftwareId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<SoftwareRequest>(e =>
        {
            e.ToTable("software_requests");
            e.HasKey(r => r.Id);
            e.Property(r => r.SoftwareName).HasMaxLength(200).IsRequired();
            e.Property(r => r.Reason).HasMaxLength(1000).IsRequired();
            e.Property(r => r.ReviewNote).HasMaxLength(1000);
            e.HasIndex(r => new { r.Status, r.CreatedAtUtc });
            e.HasIndex(r => r.StaffId);
            e.HasOne<StaffAccount>().WithMany().HasForeignKey(r => r.StaffId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<DeploymentJob>(e =>
        {
            e.ToTable("deployment_jobs");
            e.HasKey(j => j.Id);
            e.Property(j => j.Message).HasMaxLength(2000);
            e.HasIndex(j => new { j.ComputerId, j.Status });
            e.HasOne<SoftwarePackage>().WithMany().HasForeignKey(j => j.PackageId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<Computer>().WithMany().HasForeignKey(j => j.ComputerId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ControlExemption>(e =>
        {
            e.ToTable("control_exemptions");
            e.HasKey(x => x.Id);
            e.Property(x => x.Control).HasMaxLength(64);
            e.Property(x => x.Reason).HasMaxLength(500);
            e.HasIndex(x => new { x.ComputerId, x.ExpiresAtUtc });
            e.HasOne<Computer>().WithMany().HasForeignKey(x => x.ComputerId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<StaffComputerAssignment>(e =>
        {
            e.ToTable("staff_computer_assignments");
            e.HasKey(a => new { a.StaffId, a.ComputerId });
            e.HasIndex(a => a.ComputerId);
            e.HasOne<StaffAccount>().WithMany().HasForeignKey(a => a.StaffId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Computer>().WithMany().HasForeignKey(a => a.ComputerId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
