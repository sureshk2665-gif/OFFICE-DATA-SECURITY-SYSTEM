using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>
/// Software management: inventory, the approved catalog, installer packages, staff requests and
/// installation jobs. The agent only ever runs packages from jobs created here by an administrator.
/// </summary>
public sealed class SoftwareService(IServerDbContext db, AuditLog audit, IPackageStorage storage, TimeProvider clock)
{
    public const long MaxPackageBytes = 4L * 1024 * 1024 * 1024;
    public const int MaxAttempts = 3;
    public const int MaxInventoryItems = 3000;
    public const int MaxPendingRequestsPerStaff = 10;

    // ---------------------------------------------------------------- approved catalog

    public async Task<IReadOnlyList<ApprovedSoftwareResponse>> ListApprovedAsync(CancellationToken ct = default)
    {
        var items = await db.ApprovedSoftware.AsNoTracking().OrderBy(a => a.Name).ToListAsync(ct).ConfigureAwait(false);
        var packages = await db.SoftwarePackages.AsNoTracking().OrderByDescending(p => p.UploadedAtUtc).ToListAsync(ct).ConfigureAwait(false);
        return items.Select(a => ToResponse(a, packages.Where(p => p.ApprovedSoftwareId == a.Id))).ToList();
    }

    public async Task<Result<ApprovedSoftwareResponse>> CreateApprovedAsync(SaveApprovedSoftwareRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (await ValidateApprovedAsync(request, null, ct).ConfigureAwait(false) is { } error)
        {
            return error;
        }

        var item = new ApprovedSoftware
        {
            Id = Guid.NewGuid(),
            Name = request.Name.Trim(),
            Publisher = AccountRules.CleanOptional(request.Publisher),
            Notes = AccountRules.CleanOptional(request.Notes),
            CreatedAtUtc = clock.GetUtcNow(),
            CreatedByAdminId = context?.Principal?.Id ?? Guid.Empty,
        };
        db.ApprovedSoftware.Add(item);
        await audit.RecordAndSaveAsync(context!, new AuditRecord("software.approve-title", TargetType: "ApprovedSoftware", TargetId: item.Id.ToString(), Details: item.Name), ct).ConfigureAwait(false);
        return ToResponse(item, []);
    }

    public async Task<Result<ApprovedSoftwareResponse>> UpdateApprovedAsync(Guid id, SaveApprovedSoftwareRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var item = await db.ApprovedSoftware.FirstOrDefaultAsync(a => a.Id == id, ct).ConfigureAwait(false);
        if (item is null)
        {
            return ServiceError.NotFound("Approved software not found.");
        }

        if (await ValidateApprovedAsync(request, id, ct).ConfigureAwait(false) is { } error)
        {
            return error;
        }

        item.Name = request.Name.Trim();
        item.Publisher = AccountRules.CleanOptional(request.Publisher);
        item.Notes = AccountRules.CleanOptional(request.Notes);
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.update-title", TargetType: "ApprovedSoftware", TargetId: id.ToString(), Details: item.Name), ct).ConfigureAwait(false);
        var packages = await db.SoftwarePackages.AsNoTracking().Where(p => p.ApprovedSoftwareId == id).ToListAsync(ct).ConfigureAwait(false);
        return ToResponse(item, packages);
    }

    public async Task<Result<Done>> DeleteApprovedAsync(Guid id, RequestContext context, CancellationToken ct = default)
    {
        var item = await db.ApprovedSoftware.FirstOrDefaultAsync(a => a.Id == id, ct).ConfigureAwait(false);
        if (item is null)
        {
            return ServiceError.NotFound("Approved software not found.");
        }

        if (await db.SoftwarePackages.AnyAsync(p => p.ApprovedSoftwareId == id, ct).ConfigureAwait(false))
        {
            return ServiceError.Conflict("Delete this program's installer files first.");
        }

        db.ApprovedSoftware.Remove(item);
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.remove-title", TargetType: "ApprovedSoftware", TargetId: id.ToString(), Details: item.Name), ct).ConfigureAwait(false);
        return Done.Value;
    }

    // ---------------------------------------------------------------- installer packages

    public async Task<Result<SoftwarePackageResponse>> UploadPackageAsync(Guid approvedId, UploadPackageOptions options, Stream content, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(context);
        if (!await db.ApprovedSoftware.AnyAsync(a => a.Id == approvedId, ct).ConfigureAwait(false))
        {
            return ServiceError.NotFound("Approved software not found.");
        }

        if (ValidatePackageOptions(options) is { } error)
        {
            return error;
        }

        var id = Guid.NewGuid();
        StoredPackage stored;
        try
        {
            stored = await storage.SaveAsync(id, content, MaxPackageBytes, ct).ConfigureAwait(false);
        }
        catch (InvalidDataException ex)
        {
            return ServiceError.Validation(ex.Message);
        }

        if (stored.SizeBytes == 0)
        {
            storage.Delete(id);
            return ServiceError.Validation("The installer file is empty.");
        }

        var package = new SoftwarePackage
        {
            Id = id,
            ApprovedSoftwareId = approvedId,
            FileName = options.FileName.Trim(),
            Sha256 = stored.Sha256,
            SizeBytes = stored.SizeBytes,
            InstallerType = options.InstallerType,
            SilentArguments = AccountRules.CleanOptional(options.SilentArguments),
            SignerSubject = AccountRules.CleanOptional(options.SignerSubject),
            AllowUnsigned = options.AllowUnsigned,
            UploadedAtUtc = clock.GetUtcNow(),
            UploadedByAdminId = context.Principal?.Id ?? Guid.Empty,
        };
        db.SoftwarePackages.Add(package);
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.upload-package", TargetType: "SoftwarePackage", TargetId: id.ToString(),
            Details: $"{package.FileName}, SHA-256 {package.Sha256}, signer {package.SignerSubject ?? (package.AllowUnsigned ? "none (unsigned allowed)" : "none")}"), ct).ConfigureAwait(false);
        return ToResponse(package);
    }

    public async Task<Result<Done>> DeletePackageAsync(Guid id, RequestContext context, CancellationToken ct = default)
    {
        var package = await db.SoftwarePackages.FirstOrDefaultAsync(p => p.Id == id, ct).ConfigureAwait(false);
        if (package is null)
        {
            return ServiceError.NotFound("Installer not found.");
        }

        if (await db.DeploymentJobs.AnyAsync(j => j.PackageId == id, ct).ConfigureAwait(false))
        {
            return ServiceError.Conflict("This installer has been used for installations and is kept for the record.");
        }

        db.SoftwarePackages.Remove(package);
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.delete-package", TargetType: "SoftwarePackage", TargetId: id.ToString(), Details: package.FileName), ct).ConfigureAwait(false);
        storage.Delete(id);
        return Done.Value;
    }

    // ---------------------------------------------------------------- deployments

    public async Task<Result<IReadOnlyList<DeploymentResponse>>> CreateDeploymentsAsync(CreateDeploymentRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var package = await db.SoftwarePackages.AsNoTracking().FirstOrDefaultAsync(p => p.Id == request.PackageId, ct).ConfigureAwait(false);
        if (package is null)
        {
            return ServiceError.NotFound("Installer not found.");
        }

        var ids = (request.ComputerIds ?? []).Distinct().ToList();
        if (ids.Count == 0 || ids.Count > 500)
        {
            return ServiceError.Validation("Select between 1 and 500 computers.");
        }

        var computers = await db.Computers.AsNoTracking().Where(c => ids.Contains(c.Id) && c.Status == ComputerStatus.Trusted).Select(c => c.Id).ToListAsync(ct).ConfigureAwait(false);
        if (computers.Count != ids.Count)
        {
            return ServiceError.Validation("Software can only be installed on approved computers.");
        }

        var jobs = new List<DeploymentJob>();
        foreach (var computerId in computers)
        {
            jobs.Add(await QueueJobAsync(package.Id, computerId, null, context, ct).ConfigureAwait(false));
        }

        await audit.RecordAndSaveAsync(context, new AuditRecord("software.deploy", TargetType: "SoftwarePackage", TargetId: package.Id.ToString(),
            Details: $"{package.FileName} to {computers.Count} computer(s)"), ct).ConfigureAwait(false);
        return (await ListDeploymentsAsync(1, 500, null, null, jobs.Select(j => j.Id).ToList(), ct).ConfigureAwait(false)).Items.ToList();
    }

    public async Task<PagedResult<DeploymentResponse>> ListDeploymentsAsync(int page, int pageSize, Guid? computerId, string? status, IReadOnlyList<Guid>? onlyIds = null, CancellationToken ct = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = from j in db.DeploymentJobs.AsNoTracking()
                    join p in db.SoftwarePackages.AsNoTracking() on j.PackageId equals p.Id
                    join a in db.ApprovedSoftware.AsNoTracking() on p.ApprovedSoftwareId equals a.Id
                    join c in db.Computers.AsNoTracking() on j.ComputerId equals c.Id
                    select new { Job = j, p.FileName, SoftwareName = a.Name, c.Hostname };
        if (computerId is { } cid)
        {
            query = query.Where(x => x.Job.ComputerId == cid);
        }

        if (Enum.TryParse<DeploymentStatus>(status, true, out var statusFilter))
        {
            query = query.Where(x => x.Job.Status == statusFilter);
        }

        if (onlyIds is not null)
        {
            query = query.Where(x => onlyIds.Contains(x.Job.Id));
        }

        var total = await query.CountAsync(ct).ConfigureAwait(false);
        var rows = await query.OrderByDescending(x => x.Job.CreatedAtUtc).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct).ConfigureAwait(false);
        return new PagedResult<DeploymentResponse>(rows.Select(x => new DeploymentResponse(
            x.Job.Id, x.Job.PackageId, x.SoftwareName, x.FileName, x.Job.ComputerId, x.Hostname, x.Job.RequestId, x.Job.Status.ToString(),
            x.Job.Attempts, x.Job.ExitCode, x.Job.Message, x.Job.CreatedAtUtc, x.Job.FinishedAtUtc)).ToList(), page, pageSize, total);
    }

    public async Task<Result<Done>> CancelDeploymentAsync(Guid id, RequestContext context, CancellationToken ct = default)
    {
        var job = await db.DeploymentJobs.FirstOrDefaultAsync(j => j.Id == id, ct).ConfigureAwait(false);
        if (job is null)
        {
            return ServiceError.NotFound("Installation not found.");
        }

        if (job.Status != DeploymentStatus.Queued)
        {
            return ServiceError.Conflict("Only installations that have not started can be cancelled.");
        }

        job.Status = DeploymentStatus.Cancelled;
        job.FinishedAtUtc = clock.GetUtcNow();
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.cancel-deployment", TargetType: "DeploymentJob", TargetId: id.ToString()), ct).ConfigureAwait(false);
        return Done.Value;
    }

    // ---------------------------------------------------------------- staff requests

    public async Task<Result<SoftwareRequestResponse>> CreateRequestAsync(CreateSoftwareRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var principal = context?.Principal ?? throw new InvalidOperationException("A signed-in staff member is required.");
        var name = request.SoftwareName?.Trim() ?? string.Empty;
        var reason = request.Reason?.Trim() ?? string.Empty;
        if (name.Length is < 2 or > 200 || name.Any(char.IsControl))
        {
            return ServiceError.Validation("Enter the name of the software (2–200 characters).");
        }

        if (reason.Length is < 5 or > 1000)
        {
            return ServiceError.Validation("Explain why you need it (5–1000 characters).");
        }

        if (await db.SoftwareRequests.CountAsync(r => r.StaffId == principal.Id && r.Status == SoftwareRequestStatus.Pending, ct).ConfigureAwait(false) >= MaxPendingRequestsPerStaff)
        {
            return ServiceError.Conflict($"You already have {MaxPendingRequestsPerStaff} requests waiting for a decision.");
        }

        var computerId = await db.Sessions.AsNoTracking().Where(s => s.Id == principal.SessionId).Select(s => s.ComputerId).FirstOrDefaultAsync(ct).ConfigureAwait(false);
        var entity = new SoftwareRequest
        {
            Id = Guid.NewGuid(),
            StaffId = principal.Id,
            ComputerId = computerId,
            SoftwareName = name,
            Reason = reason,
            Status = SoftwareRequestStatus.Pending,
            CreatedAtUtc = clock.GetUtcNow(),
        };
        db.SoftwareRequests.Add(entity);
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.request", TargetType: "SoftwareRequest", TargetId: entity.Id.ToString(), Details: name), ct).ConfigureAwait(false);
        return (await QueryRequests().Where(x => x.Request.Id == entity.Id).ToListAsync(ct).ConfigureAwait(false)).Select(ToResponse).Single();
    }

    public async Task<IReadOnlyList<SoftwareRequestResponse>> ListMyRequestsAsync(RequestContext context, CancellationToken ct = default)
    {
        var staffId = context?.Principal?.Id ?? throw new InvalidOperationException("A signed-in staff member is required.");
        var rows = await QueryRequests().Where(x => x.Request.StaffId == staffId).OrderByDescending(x => x.Request.CreatedAtUtc).Take(100).ToListAsync(ct).ConfigureAwait(false);
        return rows.Select(ToResponse).ToList();
    }

    public async Task<PagedResult<SoftwareRequestResponse>> ListRequestsAsync(int page, int pageSize, string? status, CancellationToken ct = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = QueryRequests();
        if (Enum.TryParse<SoftwareRequestStatus>(status, true, out var statusFilter))
        {
            query = query.Where(x => x.Request.Status == statusFilter);
        }

        var total = await query.CountAsync(ct).ConfigureAwait(false);
        var rows = await query.OrderBy(x => x.Request.Status == SoftwareRequestStatus.Pending ? 0 : 1).ThenByDescending(x => x.Request.CreatedAtUtc)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct).ConfigureAwait(false);
        return new PagedResult<SoftwareRequestResponse>(rows.Select(ToResponse).ToList(), page, pageSize, total);
    }

    public async Task<Result<SoftwareRequestResponse>> ApproveRequestAsync(Guid id, ApproveSoftwareRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var entity = await db.SoftwareRequests.FirstOrDefaultAsync(r => r.Id == id, ct).ConfigureAwait(false);
        if (entity is null)
        {
            return ServiceError.NotFound("Request not found.");
        }

        if (entity.Status != SoftwareRequestStatus.Pending)
        {
            return ServiceError.Conflict("This request has already been decided.");
        }

        if (!await db.SoftwarePackages.AnyAsync(p => p.Id == request.PackageId, ct).ConfigureAwait(false))
        {
            return ServiceError.Validation("Choose an approved installer to install.");
        }

        var computerId = request.ComputerId ?? entity.ComputerId;
        if (computerId is null || !await db.Computers.AnyAsync(c => c.Id == computerId && c.Status == ComputerStatus.Trusted, ct).ConfigureAwait(false))
        {
            return ServiceError.Validation("Choose an approved computer to install on.");
        }

        var job = await QueueJobAsync(request.PackageId, computerId.Value, entity.Id, context, ct).ConfigureAwait(false);
        entity.Status = SoftwareRequestStatus.Approved;
        entity.ReviewNote = Clean(request.Note, 1000);
        entity.ReviewedByAdminId = context.Principal?.Id;
        entity.DecidedAtUtc = clock.GetUtcNow();
        entity.DeploymentJobId = job.Id;
        await audit.RecordAndSaveAsync(context, new AuditRecord("software.request.approve", TargetType: "SoftwareRequest", TargetId: id.ToString(),
            Details: $"{entity.SoftwareName} → job {job.Id}"), ct).ConfigureAwait(false);
        return (await QueryRequests().Where(x => x.Request.Id == id).ToListAsync(ct).ConfigureAwait(false)).Select(ToResponse).Single();
    }

    public async Task<Result<SoftwareRequestResponse>> RejectRequestAsync(Guid id, RejectSoftwareRequest request, RequestContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var entity = await db.SoftwareRequests.FirstOrDefaultAsync(r => r.Id == id, ct).ConfigureAwait(false);
        if (entity is null)
        {
            return ServiceError.NotFound("Request not found.");
        }

        if (entity.Status != SoftwareRequestStatus.Pending)
        {
            return ServiceError.Conflict("This request has already been decided.");
        }

        entity.Status = SoftwareRequestStatus.Rejected;
        entity.ReviewNote = Clean(request.Note, 1000);
        entity.ReviewedByAdminId = context?.Principal?.Id;
        entity.DecidedAtUtc = clock.GetUtcNow();
        await audit.RecordAndSaveAsync(context!, new AuditRecord("software.request.reject", TargetType: "SoftwareRequest", TargetId: id.ToString(), Details: entity.SoftwareName), ct).ConfigureAwait(false);
        return (await QueryRequests().Where(x => x.Request.Id == id).ToListAsync(ct).ConfigureAwait(false)).Select(ToResponse).Single();
    }

    // ---------------------------------------------------------------- inventory

    /// <summary>
    /// Stores the reported programs. After the first report (the baseline), programs that appear or
    /// disappear are recorded as security events; programs not on the approved list are flagged as warnings.
    /// </summary>
    public async Task ApplyInventoryAsync(Guid computerId, IReadOnlyList<InstalledSoftware> reported, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(reported);
        var now = clock.GetUtcNow();
        var existing = await db.InstalledSoftware.Where(i => i.ComputerId == computerId).ToListAsync(ct).ConfigureAwait(false);
        var isBaseline = existing.Count == 0;
        var approved = await db.ApprovedSoftware.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);

        var incoming = reported
            .Where(r => !string.IsNullOrWhiteSpace(r.Name))
            .Select(r => new
            {
                Name = Clean(r.Name, 256)!,
                Version = Clean(r.Version, 64) ?? string.Empty,
                Publisher = Clean(r.Publisher, 256),
                r.InstallDate,
                Scope = r.Scope == "User" ? "User" : "Machine",
            })
            .DistinctBy(r => (r.Name.ToUpperInvariant(), r.Version, r.Scope))
            .Take(MaxInventoryItems)
            .ToList();

        foreach (var item in existing)
        {
            var stillThere = incoming.Any(r => Same(item, r.Name, r.Version, r.Scope));
            if (item.IsPresent && !stillThere)
            {
                item.IsPresent = false;
                AddEvent(computerId, SecurityEventType.SoftwareRemoved, EventSeverities.Information, $"Removed: {Describe(item.Name, item.Version, item.Publisher)}", now);
            }
        }

        foreach (var r in incoming)
        {
            var item = existing.FirstOrDefault(i => Same(i, r.Name, r.Version, r.Scope));
            var isNew = item is null || !item.IsPresent;
            if (item is null)
            {
                item = new SoftwareInventoryItem { ComputerId = computerId, Name = r.Name, Version = r.Version, Scope = r.Scope, FirstSeenUtc = now };
                db.InstalledSoftware.Add(item);
            }

            item.Publisher = r.Publisher;
            item.InstallDate = r.InstallDate;
            item.IsPresent = true;
            item.LastSeenUtc = now;

            if (isNew && !isBaseline)
            {
                var ok = approved.Any(a => a.Matches(r.Name, r.Publisher));
                AddEvent(computerId, SecurityEventType.SoftwareInstalled, ok ? EventSeverities.Information : EventSeverities.Warning,
                    $"Installed{(ok ? string.Empty : " (not on the approved list)")}: {Describe(r.Name, r.Version, r.Publisher)}{(r.Scope == "User" ? " for one user" : string.Empty)}", now);
            }
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SoftwareTitleSummary>> ListTitlesAsync(string? search, bool unapprovedOnly, CancellationToken ct = default)
    {
        var query = from i in db.InstalledSoftware.AsNoTracking()
                    join c in db.Computers.AsNoTracking() on i.ComputerId equals c.Id
                    where i.IsPresent && c.Status == ComputerStatus.Trusted
                    select i;
        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = Paging.LikePattern(search);
            query = query.Where(i => EF.Functions.Like(i.Name, pattern, Paging.LikeEscape) || (i.Publisher != null && EF.Functions.Like(i.Publisher, pattern, Paging.LikeEscape)));
        }

        var rows = await query.Select(i => new { i.ComputerId, i.Name, i.Publisher, i.Version }).ToListAsync(ct).ConfigureAwait(false);
        var approved = await db.ApprovedSoftware.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
        return rows
            .GroupBy(r => (Name: r.Name, Publisher: r.Publisher ?? string.Empty))
            .Select(g => new SoftwareTitleSummary(g.Key.Name, g.Key.Publisher.Length == 0 ? null : g.Key.Publisher,
                g.Select(r => r.ComputerId).Distinct().Count(),
                g.Select(r => r.Version).Where(v => v.Length > 0).Distinct().OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList(),
                approved.Any(a => a.Matches(g.Key.Name, g.Key.Publisher))))
            .Where(t => !unapprovedOnly || !t.IsApproved)
            .OrderBy(t => t.IsApproved).ThenBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .Take(1000)
            .ToList();
    }

    public async Task<IReadOnlyList<InstalledSoftwareResponse>> ListInstallationsAsync(Guid? computerId, string? name, CancellationToken ct = default)
    {
        var query = from i in db.InstalledSoftware.AsNoTracking()
                    join c in db.Computers.AsNoTracking() on i.ComputerId equals c.Id
                    where i.IsPresent
                    select new { Item = i, c.Hostname };
        if (computerId is { } cid)
        {
            query = query.Where(x => x.Item.ComputerId == cid);
        }

        if (!string.IsNullOrWhiteSpace(name))
        {
            var exact = name.Trim();
            query = query.Where(x => x.Item.Name == exact);
        }

        var rows = await query.OrderBy(x => x.Item.Name).ThenBy(x => x.Hostname).Take(2000).ToListAsync(ct).ConfigureAwait(false);
        var approved = await db.ApprovedSoftware.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
        return rows.Select(x => new InstalledSoftwareResponse(x.Item.ComputerId, x.Hostname, x.Item.Name, x.Item.Version.Length == 0 ? null : x.Item.Version,
            x.Item.Publisher, x.Item.Scope, approved.Any(a => a.Matches(x.Item.Name, x.Item.Publisher)), x.Item.FirstSeenUtc)).ToList();
    }

    // ---------------------------------------------------------------- agent side of installation jobs

    public Task<int> CountPendingJobsAsync(Guid computerId, CancellationToken ct = default) =>
        db.DeploymentJobs.CountAsync(j => j.ComputerId == computerId && (j.Status == DeploymentStatus.Queued || j.Status == DeploymentStatus.Running), ct);

    /// <summary>Queued jobs, plus running ones (the agent may have restarted during an installation).</summary>
    public async Task<IReadOnlyList<AgentJob>> GetAgentJobsAsync(Guid computerId, CancellationToken ct = default)
    {
        var rows = await (from j in db.DeploymentJobs.AsNoTracking()
                          join p in db.SoftwarePackages.AsNoTracking() on j.PackageId equals p.Id
                          join a in db.ApprovedSoftware.AsNoTracking() on p.ApprovedSoftwareId equals a.Id
                          where j.ComputerId == computerId && (j.Status == DeploymentStatus.Queued || j.Status == DeploymentStatus.Running)
                          orderby j.CreatedAtUtc
                          select new AgentJob(j.Id, a.Name, p.FileName, p.Sha256, p.SizeBytes, p.InstallerType, p.SilentArguments, p.SignerSubject, p.AllowUnsigned))
            .Take(20).ToListAsync(ct).ConfigureAwait(false);
        return rows;
    }

    public async Task<Result<Done>> StartJobAsync(Guid computerId, Guid jobId, CancellationToken ct = default)
    {
        var job = await db.DeploymentJobs.FirstOrDefaultAsync(j => j.Id == jobId && j.ComputerId == computerId, ct).ConfigureAwait(false);
        if (job is null || job.Status is not (DeploymentStatus.Queued or DeploymentStatus.Running))
        {
            return ServiceError.NotFound("No such installation for this computer.");
        }

        var now = clock.GetUtcNow();
        job.Attempts++;
        if (job.Attempts > MaxAttempts)
        {
            job.Status = DeploymentStatus.Failed;
            job.Message = $"Gave up after {MaxAttempts} attempts (the computer restarted or lost connection during installation).";
            job.FinishedAtUtc = now;
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return ServiceError.Conflict(job.Message);
        }

        job.Status = DeploymentStatus.Running;
        job.StartedAtUtc = now;
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return Done.Value;
    }

    /// <summary>Opens the installer for a running job of this computer; any other request is refused.</summary>
    public async Task<(Stream Content, string FileName)?> OpenJobPackageAsync(Guid computerId, Guid jobId, CancellationToken ct = default)
    {
        var package = await (from j in db.DeploymentJobs.AsNoTracking()
                             join p in db.SoftwarePackages.AsNoTracking() on j.PackageId equals p.Id
                             where j.Id == jobId && j.ComputerId == computerId && j.Status == DeploymentStatus.Running
                             select p).FirstOrDefaultAsync(ct).ConfigureAwait(false);
        return package is null ? null : (storage.OpenRead(package.Id), package.FileName);
    }

    public async Task<Result<Done>> CompleteJobAsync(Guid computerId, Guid jobId, AgentJobResult result, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        var job = await db.DeploymentJobs.FirstOrDefaultAsync(j => j.Id == jobId && j.ComputerId == computerId, ct).ConfigureAwait(false);
        if (job is null || job.Status != DeploymentStatus.Running)
        {
            return ServiceError.NotFound("No running installation with this id for this computer.");
        }

        if (!Enum.TryParse<DeploymentStatus>(result.Status, out var status) ||
            status is not (DeploymentStatus.Succeeded or DeploymentStatus.SucceededRebootRequired or DeploymentStatus.Failed))
        {
            return ServiceError.Validation("Status must be Succeeded, SucceededRebootRequired or Failed.");
        }

        var now = clock.GetUtcNow();
        job.Status = status;
        job.ExitCode = result.ExitCode;
        job.Message = Clean(result.Message, 2000);
        job.FinishedAtUtc = now;
        var package = await db.SoftwarePackages.AsNoTracking().FirstAsync(p => p.Id == job.PackageId, ct).ConfigureAwait(false);
        AddEvent(computerId, SecurityEventType.SoftwareDeployment, status == DeploymentStatus.Failed ? EventSeverities.Warning : EventSeverities.Information,
            $"Approved installation of {package.FileName}: {status}{(result.ExitCode is { } code ? $" (exit code {code})" : string.Empty)}", now);
        await audit.RecordAndSaveAsync(RequestContext.System, new AuditRecord("software.deployment-result", status == DeploymentStatus.Failed ? AuditOutcome.Failure : AuditOutcome.Success,
            TargetType: "DeploymentJob", TargetId: jobId.ToString(), Details: $"{package.FileName}: {status} {result.ExitCode}", ActorTypeOverride: AuditActorType.Computer, ActorIdOverride: computerId), ct).ConfigureAwait(false);
        return Done.Value;
    }

    // ---------------------------------------------------------------- helpers

    private async Task<DeploymentJob> QueueJobAsync(Guid packageId, Guid computerId, Guid? requestId, RequestContext context, CancellationToken ct)
    {
        var existing = await db.DeploymentJobs.FirstOrDefaultAsync(j => j.PackageId == packageId && j.ComputerId == computerId &&
            (j.Status == DeploymentStatus.Queued || j.Status == DeploymentStatus.Running), ct).ConfigureAwait(false);
        if (existing is not null)
        {
            existing.RequestId ??= requestId;
            return existing;
        }

        var job = new DeploymentJob
        {
            Id = Guid.NewGuid(),
            PackageId = packageId,
            ComputerId = computerId,
            RequestId = requestId,
            Status = DeploymentStatus.Queued,
            CreatedAtUtc = clock.GetUtcNow(),
            CreatedByAdminId = context.Principal?.Id ?? Guid.Empty,
        };
        db.DeploymentJobs.Add(job);
        return job;
    }

    private void AddEvent(Guid computerId, SecurityEventType type, string severity, string details, DateTimeOffset now) =>
        db.SecurityEvents.Add(new SecurityEvent
        {
            ComputerId = computerId,
            EventId = Guid.NewGuid(),
            EventType = type.ToString(),
            Severity = severity,
            OccurredAtUtc = now,
            ReceivedAtUtc = now,
            Details = Clean(details, 2000),
        });

    private IQueryable<RequestRow> QueryRequests() =>
        from r in db.SoftwareRequests.AsNoTracking()
        join s in db.Staff.AsNoTracking() on r.StaffId equals s.Id
        join c in db.Computers.AsNoTracking() on r.ComputerId equals c.Id into cj
        from c in cj.DefaultIfEmpty()
        join j in db.DeploymentJobs.AsNoTracking() on r.DeploymentJobId equals j.Id into jj
        from j in jj.DefaultIfEmpty()
        select new RequestRow(r, s.DisplayName, s.EmployeeCode, c == null ? null : c.Hostname, j == null ? null : (DeploymentStatus?)j.Status);

    private sealed record RequestRow(SoftwareRequest Request, string StaffName, string EmployeeCode, string? ComputerName, DeploymentStatus? JobStatus);

    private static SoftwareRequestResponse ToResponse(RequestRow x) => new(
        x.Request.Id, x.Request.StaffId, x.StaffName, x.EmployeeCode, x.Request.ComputerId, x.ComputerName, x.Request.SoftwareName, x.Request.Reason,
        x.Request.Status.ToString(), x.Request.ReviewNote, x.JobStatus?.ToString(), x.Request.CreatedAtUtc, x.Request.DecidedAtUtc);

    private async Task<ServiceError?> ValidateApprovedAsync(SaveApprovedSoftwareRequest request, Guid? id, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length is < 2 or > 256)
        {
            return ServiceError.Validation("Enter the program name as it appears in Windows 'Installed apps' (2–256 characters).");
        }

        if (request.Publisher?.Trim().Length > 256 || request.Notes?.Trim().Length > 1000)
        {
            return ServiceError.Validation("Publisher (256) or notes (1000 characters) are too long.");
        }

        var name = request.Name.Trim();
        return await db.ApprovedSoftware.AnyAsync(a => a.Name == name && a.Id != id, ct).ConfigureAwait(false)
            ? ServiceError.Conflict($"'{name}' is already on the approved list.")
            : null;
    }

    private static ServiceError? ValidatePackageOptions(UploadPackageOptions options)
    {
        var fileName = options.FileName?.Trim() ?? string.Empty;
        if (fileName.Length is 0 or > 200 || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || fileName.Contains("..", StringComparison.Ordinal) ||
            fileName.IndexOfAny(['/', '\\', ':']) >= 0)
        {
            return ServiceError.Validation("The installer file name is not valid.");
        }

        var extension = Path.GetExtension(fileName).ToUpperInvariant();
        if (!((options.InstallerType == InstallerTypes.Msi && extension == ".MSI") || (options.InstallerType == InstallerTypes.Exe && extension == ".EXE")))
        {
            return ServiceError.Validation("Installer type must be Msi for .msi files or Exe for .exe files.");
        }

        if (options.SilentArguments is { } args && (args.Length > 512 || args.Any(char.IsControl)))
        {
            return ServiceError.Validation("Silent install options must be one line of at most 512 characters.");
        }

        if (options.InstallerType == InstallerTypes.Exe && string.IsNullOrWhiteSpace(options.SilentArguments))
        {
            return ServiceError.Validation("EXE installers need silent install options (for example /S or /quiet), otherwise they wait for someone to click.");
        }

        if (options.SignerSubject is { Length: > 512 })
        {
            return ServiceError.Validation("Signer name is too long.");
        }

        return string.IsNullOrWhiteSpace(options.SignerSubject) && !options.AllowUnsigned
            ? ServiceError.Validation("This installer has no digital signature. Tick 'allow unsigned installer' only if you trust its source.")
            : null;
    }

    private static bool Same(SoftwareInventoryItem item, string name, string version, string scope) =>
        string.Equals(item.Name, name, StringComparison.OrdinalIgnoreCase) && item.Version == version && item.Scope == scope;

    private static string Describe(string name, string? version, string? publisher) =>
        $"{name}{(string.IsNullOrEmpty(version) ? string.Empty : " " + version)}{(publisher is null ? string.Empty : $" ({publisher})")}";

    private static string? Clean(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = new string(value.Trim().Where(c => !char.IsControl(c) || c is '\n' or '\r').ToArray());
        return text.Length <= max ? text : text[..max];
    }

    private static ApprovedSoftwareResponse ToResponse(ApprovedSoftware a, IEnumerable<SoftwarePackage> packages) =>
        new(a.Id, a.Name, a.Publisher, a.Notes, a.CreatedAtUtc, packages.Select(ToResponse).ToList());

    private static SoftwarePackageResponse ToResponse(SoftwarePackage p) =>
        new(p.Id, p.ApprovedSoftwareId, p.FileName, p.Sha256, p.SizeBytes, p.InstallerType, p.SilentArguments, p.SignerSubject, p.AllowUnsigned, p.UploadedAtUtc);
}
