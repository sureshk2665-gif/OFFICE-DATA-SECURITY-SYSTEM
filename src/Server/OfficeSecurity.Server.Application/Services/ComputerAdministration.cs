using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Security;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Administrator operations on computers: enrollment codes, approval, retirement and assignments.</summary>
public sealed class ComputerAdministration(
    IServerDbContext db,
    AuditLog audit,
    IDeviceCertificateAuthority certificateAuthority,
    TimeProvider clock)
{
    public static readonly TimeSpan EnrollmentCodeLifetime = TimeSpan.FromHours(24);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<EnrollmentCodeResponse> CreateEnrollmentCodeAsync(RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var code = SecretCodes.NewSetupCode();
        var now = clock.GetUtcNow();
        var entity = new EnrollmentCode
        {
            Id = Guid.NewGuid(),
            CodeHash = SecretCodes.HashForStorage(SecretCodes.NormalizeSetupCode(code)),
            CreatedAtUtc = now,
            ExpiresAtUtc = now + EnrollmentCodeLifetime,
            CreatedByAdminId = context.Principal?.Id ?? Guid.Empty,
        };
        db.EnrollmentCodes.Add(entity);
        await audit.RecordAndSaveAsync(context, new AuditRecord("computer.enrollment-code.create", TargetType: "EnrollmentCode", TargetId: entity.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return new EnrollmentCodeResponse(code, entity.ExpiresAtUtc, PairingCode.Compute(certificateAuthority.CaCertificateDer));
    }

    public async Task<PagedResult<ComputerSummary>> ListAsync(int page, int pageSize, string? search, string? status, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = db.Computers.AsNoTracking();
        if (Enum.TryParse<ComputerStatus>(status, ignoreCase: true, out var statusFilter))
        {
            query = query.Where(c => c.Status == statusFilter);
        }
        else
        {
            // Rejected and retired computers are hidden unless asked for explicitly.
            query = query.Where(c => c.Status == ComputerStatus.Trusted || c.Status == ComputerStatus.PendingApproval);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = Paging.LikePattern(search);
            query = query.Where(c => EF.Functions.Like(c.Hostname, pattern, Paging.LikeEscape) ||
                                     (c.OsName != null && EF.Functions.Like(c.OsName, pattern, Paging.LikeEscape)));
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query
            .OrderBy(c => c.Status == ComputerStatus.PendingApproval ? 0 : 1)
            .ThenBy(c => c.Hostname)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var policyNames = await PolicyNamesAsync(cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        return new PagedResult<ComputerSummary>(rows.Select(c => ToSummary(c, policyNames, now)).ToList(), page, pageSize, total);
    }

    public async Task<Result<ComputerDetail>> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var computer = await db.Computers.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, cancellationToken).ConfigureAwait(false);
        if (computer is null)
        {
            return ServiceError.NotFound("Computer not found.");
        }

        var devices = await db.Devices.AsNoTracking().Where(d => d.ComputerId == id)
            .OrderByDescending(d => d.IsConnected).ThenByDescending(d => d.LastSeenUtc)
            .Take(200)
            .Select(d => new DeviceSummary(d.InstanceId, d.Name, d.DeviceClass, d.Manufacturer, d.IsConnected, d.FirstSeenUtc, d.LastSeenUtc, d.ParentInstanceId))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var staff = await (from a in db.StaffAssignments.AsNoTracking()
                           join s in db.Staff.AsNoTracking() on a.StaffId equals s.Id
                           where a.ComputerId == id
                           orderby s.DisplayName
                           select new StaffReference(s.Id, s.EmployeeCode, s.DisplayName))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var policyNames = await PolicyNamesAsync(cancellationToken).ConfigureAwait(false);

        return new ComputerDetail(
            ToSummary(computer, policyNames, clock.GetUtcNow()),
            computer.HardwareJson is null ? null : JsonSerializer.Deserialize<HardwareInventory>(computer.HardwareJson, Json),
            computer.ControlStatusJson is null ? [] : JsonSerializer.Deserialize<List<ControlStatus>>(computer.ControlStatusJson, Json) ?? [],
            devices,
            staff,
            computer.PolicyId,
            computer.LastSeenIp,
            computer.CertificateThumbprint,
            computer.CertificateExpiresAtUtc);
    }

    public async Task<Result<ComputerSummary>> ApproveAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var computer = await db.Computers.FirstOrDefaultAsync(c => c.Id == id, cancellationToken).ConfigureAwait(false);
        if (computer is null)
        {
            return ServiceError.NotFound("Computer not found.");
        }

        if (computer.Status != ComputerStatus.PendingApproval || computer.CertificateRequestPem is null)
        {
            return ServiceError.Conflict("Only computers waiting for approval can be approved.");
        }

        var issued = certificateAuthority.IssueComputerCertificate(computer.CertificateRequestPem, computer.Id);
        computer.CertificatePem = issued.CertificatePem;
        computer.CertificateThumbprint = issued.Thumbprint;
        computer.CertificateExpiresAtUtc = issued.ExpiresAtUtc;
        computer.Status = ComputerStatus.Trusted;
        computer.DecidedAtUtc = clock.GetUtcNow();
        computer.DecidedByAdminId = context?.Principal?.Id;

        await audit.RecordAndSaveAsync(context!, new AuditRecord("computer.approve", TargetType: "Computer", TargetId: computer.Id.ToString(),
            Details: computer.Hostname), cancellationToken).ConfigureAwait(false);
        return ToSummary(computer, await PolicyNamesAsync(cancellationToken).ConfigureAwait(false), clock.GetUtcNow());
    }

    public Task<Result<ComputerSummary>> RejectAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default) =>
        ChangeStatusAsync(id, ComputerStatus.PendingApproval, ComputerStatus.Rejected, "computer.reject",
            "Only computers waiting for approval can be rejected.", context, cancellationToken);

    /// <summary>Removes a computer from management; its certificate stops being accepted immediately.</summary>
    public Task<Result<ComputerSummary>> RetireAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default) =>
        ChangeStatusAsync(id, ComputerStatus.Trusted, ComputerStatus.Retired, "computer.retire",
            "Only approved computers can be removed from management.", context, cancellationToken);

    public async Task<Result<ComputerSummary>> AssignPolicyAsync(Guid id, AssignPolicyRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var computer = await db.Computers.FirstOrDefaultAsync(c => c.Id == id, cancellationToken).ConfigureAwait(false);
        if (computer is null)
        {
            return ServiceError.NotFound("Computer not found.");
        }

        if (request.PolicyId is { } policyId && !await db.Policies.AnyAsync(p => p.Id == policyId, cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.Validation("The selected policy does not exist.");
        }

        var target = request.PolicyId is { } pid && await db.Policies.AnyAsync(p => p.Id == pid && p.IsDefault, cancellationToken).ConfigureAwait(false)
            ? null
            : request.PolicyId;
        if (computer.PolicyId != target)
        {
            computer.PolicyId = target;
            computer.PolicyVersion++;
        }

        await audit.RecordAndSaveAsync(context, new AuditRecord("computer.assign-policy", TargetType: "Computer", TargetId: computer.Id.ToString(),
            Details: target?.ToString() ?? "default policy"), cancellationToken).ConfigureAwait(false);
        return ToSummary(computer, await PolicyNamesAsync(cancellationToken).ConfigureAwait(false), clock.GetUtcNow());
    }

    public async Task<Result<IReadOnlyList<StaffReference>>> AssignStaffAsync(Guid id, AssignStaffRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        if (!await db.Computers.AnyAsync(c => c.Id == id, cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.NotFound("Computer not found.");
        }

        var wanted = (request.StaffIds ?? []).Distinct().ToList();
        if (wanted.Count > 500)
        {
            return ServiceError.Validation("Too many staff members in one request.");
        }

        var staff = await db.Staff.AsNoTracking().Where(s => wanted.Contains(s.Id))
            .Select(s => new StaffReference(s.Id, s.EmployeeCode, s.DisplayName))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        if (staff.Count != wanted.Count)
        {
            return ServiceError.Validation("One or more staff members do not exist.");
        }

        var existing = await db.StaffAssignments.Where(a => a.ComputerId == id).ToListAsync(cancellationToken).ConfigureAwait(false);
        db.StaffAssignments.RemoveRange(existing.Where(a => !wanted.Contains(a.StaffId)));
        var now = clock.GetUtcNow();
        foreach (var staffId in wanted.Where(w => existing.All(a => a.StaffId != w)))
        {
            db.StaffAssignments.Add(new StaffComputerAssignment
            {
                StaffId = staffId,
                ComputerId = id,
                AssignedAtUtc = now,
                AssignedByAdminId = context.Principal?.Id ?? Guid.Empty,
            });
        }

        await audit.RecordAndSaveAsync(context, new AuditRecord("computer.assign-staff", TargetType: "Computer", TargetId: id.ToString(),
            Details: string.Join(", ", staff.Select(s => s.EmployeeCode))), cancellationToken).ConfigureAwait(false);
        return staff.OrderBy(s => s.DisplayName).ToList();
    }

    public async Task<PagedResult<SecurityEventResponse>> ListEventsAsync(int page, int pageSize, Guid? computerId, string? search,
        string? severity = null, string? type = null, DateTimeOffset? from = null, DateTimeOffset? to = null, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = from e in db.SecurityEvents.AsNoTracking()
                    join c in db.Computers.AsNoTracking() on e.ComputerId equals c.Id
                    select new { Event = e, c.Hostname };
        if (computerId is { } cid)
        {
            query = query.Where(x => x.Event.ComputerId == cid);
        }

        if (!string.IsNullOrWhiteSpace(severity))
        {
            query = query.Where(x => x.Event.Severity == severity);
        }

        if (!string.IsNullOrWhiteSpace(type))
        {
            query = query.Where(x => x.Event.EventType == type);
        }

        if (from is { } start)
        {
            query = query.Where(x => x.Event.OccurredAtUtc >= start);
        }

        if (to is { } end)
        {
            query = query.Where(x => x.Event.OccurredAtUtc < end);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = Paging.LikePattern(search);
            query = query.Where(x => EF.Functions.Like(x.Event.EventType, pattern, Paging.LikeEscape) ||
                                     EF.Functions.Like(x.Hostname, pattern, Paging.LikeEscape) ||
                                     (x.Event.Details != null && EF.Functions.Like(x.Event.Details, pattern, Paging.LikeEscape)));
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(x => x.Event.OccurredAtUtc).ThenByDescending(x => x.Event.Id)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return new PagedResult<SecurityEventResponse>(
            rows.Select(x => new SecurityEventResponse(x.Event.Id, x.Event.ComputerId, x.Hostname, x.Event.EventType, x.Event.Severity,
                x.Event.OccurredAtUtc, x.Event.ReceivedAtUtc, x.Event.Details)).ToList(),
            page, pageSize, total);
    }

    private async Task<Result<ComputerSummary>> ChangeStatusAsync(Guid id, ComputerStatus from, ComputerStatus to, string action, string conflict,
        RequestContext context, CancellationToken cancellationToken)
    {
        var computer = await db.Computers.FirstOrDefaultAsync(c => c.Id == id, cancellationToken).ConfigureAwait(false);
        if (computer is null)
        {
            return ServiceError.NotFound("Computer not found.");
        }

        if (computer.Status != from)
        {
            return ServiceError.Conflict(conflict);
        }

        computer.Status = to;
        computer.PollTokenHash = null;
        computer.DecidedAtUtc = clock.GetUtcNow();
        computer.DecidedByAdminId = context.Principal?.Id;
        await audit.RecordAndSaveAsync(context, new AuditRecord(action, TargetType: "Computer", TargetId: computer.Id.ToString(), Details: computer.Hostname), cancellationToken).ConfigureAwait(false);
        return ToSummary(computer, await PolicyNamesAsync(cancellationToken).ConfigureAwait(false), clock.GetUtcNow());
    }

    /// <summary>Policy names by id; <see cref="Guid.Empty"/> maps to the default policy's name.</summary>
    private async Task<Dictionary<Guid, string>> PolicyNamesAsync(CancellationToken cancellationToken)
    {
        var policies = await db.Policies.AsNoTracking().Select(p => new { p.Id, p.Name, p.IsDefault }).ToListAsync(cancellationToken).ConfigureAwait(false);
        var names = policies.ToDictionary(p => p.Id, p => p.Name);
        names[Guid.Empty] = policies.FirstOrDefault(p => p.IsDefault)?.Name ?? PolicyService.DefaultPolicyName;
        return names;
    }

    private static ComputerSummary ToSummary(Computer c, Dictionary<Guid, string> policyNames, DateTimeOffset now) => new(
        c.Id,
        c.Hostname,
        c.Status.ToString(),
        c.Status == ComputerStatus.Trusted && ComputerPresence.IsOnline(c.LastSeenAtUtc, c.HeartbeatIntervalSeconds, now),
        c.LastSeenAtUtc,
        c.OsName,
        c.OsEdition,
        c.AgentVersion,
        policyNames.GetValueOrDefault(c.PolicyId ?? Guid.Empty, PolicyService.DefaultPolicyName),
        c.AppliedPolicyVersion,
        c.PolicyVersion,
        c.FailedControls,
        c.RegisteredAtUtc);
}
