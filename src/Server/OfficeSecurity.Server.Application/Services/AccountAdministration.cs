using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Security;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>
/// Administrator operations on staff and administrator accounts. Administrators never see or set
/// another person's password: they issue one-time setup codes instead.
/// </summary>
public sealed class AccountAdministration(
    IServerDbContext db,
    AuditLog audit,
    AuthService auth,
    IOptions<SecurityOptions> options,
    TimeProvider clock)
{
    private readonly SecurityOptions _options = options.Value;

    // ---------------------------------------------------------------- staff

    public async Task<PagedResult<StaffSummary>> ListStaffAsync(int page, int pageSize, string? search, string? status, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Paging.Normalize(page, pageSize);
        var query = db.Staff.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = Paging.LikePattern(search);
            query = query.Where(s => EF.Functions.Like(s.EmployeeCode, pattern, Paging.LikeEscape) ||
                                     EF.Functions.Like(s.DisplayName, pattern, Paging.LikeEscape) ||
                                     (s.Department != null && EF.Functions.Like(s.Department, pattern, Paging.LikeEscape)));
        }

        if (Enum.TryParse<AccountStatus>(status, ignoreCase: true, out var statusFilter))
        {
            query = query.Where(s => s.Status == statusFilter);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderBy(s => s.DisplayName).ThenBy(s => s.EmployeeCode)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        return new PagedResult<StaffSummary>(rows.Select(s => ToSummary(s, now)).ToList(), page, pageSize, total);
    }

    public async Task<Result<StaffSummary>> GetStaffAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var staff = await db.Staff.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, cancellationToken).ConfigureAwait(false);
        return staff is null ? ServiceError.NotFound("Staff account not found.") : ToSummary(staff, clock.GetUtcNow());
    }

    public async Task<Result<SetupCodeResponse>> CreateStaffAsync(CreateStaffRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var error = AccountRules.ValidateEmployeeCode(request.EmployeeCode)
                    ?? AccountRules.ValidateDisplayName(request.DisplayName)
                    ?? AccountRules.ValidateDepartment(request.Department);
        if (error is not null)
        {
            return ServiceError.Validation(error);
        }

        var normalized = AccountRules.Normalize(request.EmployeeCode);
        if (await db.Staff.AnyAsync(s => s.NormalizedEmployeeCode == normalized, cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.Conflict($"A staff account with employee code '{request.EmployeeCode.Trim()}' already exists.");
        }

        var now = clock.GetUtcNow();
        var staff = new StaffAccount
        {
            Id = Guid.NewGuid(),
            EmployeeCode = request.EmployeeCode.Trim(),
            NormalizedEmployeeCode = normalized,
            DisplayName = request.DisplayName.Trim(),
            Department = AccountRules.CleanOptional(request.Department),
            Status = AccountStatus.PendingActivation,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
        };
        db.Staff.Add(staff);
        var code = IssueSetupCode(PrincipalType.Staff, staff.Id, context, now);

        await audit.RecordAndSaveAsync(context, new AuditRecord("staff.create", TargetType: "Staff", TargetId: staff.Id.ToString(),
            Details: $"employee code {staff.EmployeeCode}"), cancellationToken).ConfigureAwait(false);
        return new SetupCodeResponse(staff.Id, staff.EmployeeCode, code, now + _options.SetupCodeLifetime);
    }

    public async Task<Result<StaffSummary>> UpdateStaffAsync(Guid id, UpdateStaffRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var error = AccountRules.ValidateDisplayName(request.DisplayName) ?? AccountRules.ValidateDepartment(request.Department);
        if (error is not null)
        {
            return ServiceError.Validation(error);
        }

        var staff = await db.Staff.FirstOrDefaultAsync(s => s.Id == id, cancellationToken).ConfigureAwait(false);
        if (staff is null)
        {
            return ServiceError.NotFound("Staff account not found.");
        }

        staff.DisplayName = request.DisplayName.Trim();
        staff.Department = AccountRules.CleanOptional(request.Department);
        staff.UpdatedAtUtc = clock.GetUtcNow();
        await audit.RecordAndSaveAsync(context, new AuditRecord("staff.update", TargetType: "Staff", TargetId: staff.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return ToSummary(staff, clock.GetUtcNow());
    }

    public async Task<Result<StaffSummary>> DisableStaffAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var staff = await db.Staff.FirstOrDefaultAsync(s => s.Id == id, cancellationToken).ConfigureAwait(false);
        if (staff is null)
        {
            return ServiceError.NotFound("Staff account not found.");
        }

        var now = clock.GetUtcNow();
        staff.Status = AccountStatus.Disabled;
        staff.UpdatedAtUtc = now;
        await RevokeSetupCodesAsync(PrincipalType.Staff, staff.Id, now, cancellationToken).ConfigureAwait(false);
        await auth.EndSessionsAsync(PrincipalType.Staff, staff.Id, now, "account disabled", null, cancellationToken).ConfigureAwait(false);
        await audit.RecordAndSaveAsync(context, new AuditRecord("staff.disable", TargetType: "Staff", TargetId: staff.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return ToSummary(staff, now);
    }

    public async Task<Result<StaffSummary>> EnableStaffAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var staff = await db.Staff.FirstOrDefaultAsync(s => s.Id == id, cancellationToken).ConfigureAwait(false);
        if (staff is null)
        {
            return ServiceError.NotFound("Staff account not found.");
        }

        var now = clock.GetUtcNow();
        staff.Status = staff.PasswordHash is null ? AccountStatus.PendingActivation : AccountStatus.Active;
        staff.FailedLoginCount = 0;
        staff.LockedUntilUtc = null;
        staff.UpdatedAtUtc = now;
        await audit.RecordAndSaveAsync(context, new AuditRecord("staff.enable", TargetType: "Staff", TargetId: staff.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return ToSummary(staff, now);
    }

    /// <summary>Clears the password and issues a new one-time setup code (e.g. the employee forgot the password).</summary>
    public async Task<Result<SetupCodeResponse>> ResetStaffAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var staff = await db.Staff.FirstOrDefaultAsync(s => s.Id == id, cancellationToken).ConfigureAwait(false);
        if (staff is null)
        {
            return ServiceError.NotFound("Staff account not found.");
        }

        if (staff.Status == AccountStatus.Disabled)
        {
            return ServiceError.Conflict("Enable the account before issuing a new setup code.");
        }

        var now = clock.GetUtcNow();
        staff.PasswordHash = null;
        staff.Status = AccountStatus.PendingActivation;
        staff.FailedLoginCount = 0;
        staff.LockedUntilUtc = null;
        staff.UpdatedAtUtc = now;
        await RevokeSetupCodesAsync(PrincipalType.Staff, staff.Id, now, cancellationToken).ConfigureAwait(false);
        await auth.EndSessionsAsync(PrincipalType.Staff, staff.Id, now, "credentials reset", null, cancellationToken).ConfigureAwait(false);
        var code = IssueSetupCode(PrincipalType.Staff, staff.Id, context, now);

        await audit.RecordAndSaveAsync(context, new AuditRecord("staff.reset", TargetType: "Staff", TargetId: staff.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return new SetupCodeResponse(staff.Id, staff.EmployeeCode, code, now + _options.SetupCodeLifetime);
    }

    // ---------------------------------------------------------------- administrators (SuperAdmin only)

    public async Task<IReadOnlyList<AdminSummary>> ListAdminsAsync(CancellationToken cancellationToken = default)
    {
        var admins = await db.Admins.AsNoTracking().OrderBy(a => a.Username).ToListAsync(cancellationToken).ConfigureAwait(false);
        return admins.Select(ToSummary).ToList();
    }

    public async Task<Result<SetupCodeResponse>> CreateAdminAsync(CreateAdminRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (RequireSuperAdmin(context) is { } forbidden)
        {
            return forbidden;
        }

        var error = AccountRules.ValidateUsername(request.Username) ?? AccountRules.ValidateDisplayName(request.DisplayName);
        if (error is not null)
        {
            return ServiceError.Validation(error);
        }

        if (!Enum.TryParse<AdminRole>(request.Role, ignoreCase: false, out var role) || !Enum.IsDefined(role))
        {
            return ServiceError.Validation($"Role must be one of: {string.Join(", ", AdminRoles.All)}.");
        }

        var normalized = AccountRules.Normalize(request.Username);
        if (await db.Admins.AnyAsync(a => a.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.Conflict($"An administrator named '{request.Username.Trim()}' already exists.");
        }

        var now = clock.GetUtcNow();
        var admin = new AdminAccount
        {
            Id = Guid.NewGuid(),
            Username = request.Username.Trim(),
            NormalizedUsername = normalized,
            DisplayName = request.DisplayName.Trim(),
            Role = role,
            Status = AccountStatus.PendingActivation,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
        };
        db.Admins.Add(admin);
        var code = IssueSetupCode(PrincipalType.Admin, admin.Id, context, now);

        await audit.RecordAndSaveAsync(context, new AuditRecord("admin.create", TargetType: "Admin", TargetId: admin.Id.ToString(),
            Details: $"user name {admin.Username}, role {role}"), cancellationToken).ConfigureAwait(false);
        return new SetupCodeResponse(admin.Id, admin.Username, code, now + _options.SetupCodeLifetime);
    }

    public async Task<Result<AdminSummary>> DisableAdminAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var (admin, error) = await LoadAdminForChangeAsync(id, context, cancellationToken).ConfigureAwait(false);
        if (error is not null)
        {
            return error;
        }

        var now = clock.GetUtcNow();
        admin!.Status = AccountStatus.Disabled;
        admin.UpdatedAtUtc = now;
        await RevokeSetupCodesAsync(PrincipalType.Admin, admin.Id, now, cancellationToken).ConfigureAwait(false);
        await auth.EndSessionsAsync(PrincipalType.Admin, admin.Id, now, "account disabled", null, cancellationToken).ConfigureAwait(false);
        await audit.RecordAndSaveAsync(context, new AuditRecord("admin.disable", TargetType: "Admin", TargetId: admin.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return ToSummary(admin);
    }

    public async Task<Result<AdminSummary>> EnableAdminAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        if (RequireSuperAdmin(context) is { } forbidden)
        {
            return forbidden;
        }

        var admin = await db.Admins.FirstOrDefaultAsync(a => a.Id == id, cancellationToken).ConfigureAwait(false);
        if (admin is null)
        {
            return ServiceError.NotFound("Administrator not found.");
        }

        var now = clock.GetUtcNow();
        admin.Status = admin.PasswordHash is not null && admin.MfaEnabled ? AccountStatus.Active : AccountStatus.PendingActivation;
        admin.FailedLoginCount = 0;
        admin.LockedUntilUtc = null;
        admin.UpdatedAtUtc = now;
        await audit.RecordAndSaveAsync(context, new AuditRecord("admin.enable", TargetType: "Admin", TargetId: admin.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return ToSummary(admin);
    }

    /// <summary>Clears password and two-step verification, and issues a new setup code (e.g. lost phone).</summary>
    public async Task<Result<SetupCodeResponse>> ResetAdminAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var (admin, error) = await LoadAdminForChangeAsync(id, context, cancellationToken).ConfigureAwait(false);
        if (error is not null)
        {
            return error;
        }

        var now = clock.GetUtcNow();
        admin!.PasswordHash = null;
        admin.TotpSecretProtected = null;
        admin.MfaEnabled = false;
        admin.LastTotpTimeStep = 0;
        admin.Status = AccountStatus.PendingActivation;
        admin.FailedLoginCount = 0;
        admin.LockedUntilUtc = null;
        admin.UpdatedAtUtc = now;
        await RevokeSetupCodesAsync(PrincipalType.Admin, admin.Id, now, cancellationToken).ConfigureAwait(false);
        await auth.EndSessionsAsync(PrincipalType.Admin, admin.Id, now, "credentials reset", null, cancellationToken).ConfigureAwait(false);
        var code = IssueSetupCode(PrincipalType.Admin, admin.Id, context, now);

        await audit.RecordAndSaveAsync(context, new AuditRecord("admin.reset", TargetType: "Admin", TargetId: admin.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return new SetupCodeResponse(admin.Id, admin.Username, code, now + _options.SetupCodeLifetime);
    }

    // ---------------------------------------------------------------- dashboard

    public async Task<DashboardOverviewResponse> GetOverviewAsync(CancellationToken cancellationToken = default)
    {
        var counts = await db.Staff.AsNoTracking()
            .GroupBy(s => s.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        int Count(AccountStatus status) => counts.FirstOrDefault(c => c.Status == status)?.Count ?? 0;

        var admins = await db.Admins.CountAsync(a => a.Status == AccountStatus.Active, cancellationToken).ConfigureAwait(false);
        var since = clock.GetUtcNow().AddHours(-24);
        var failedLogins = await db.AuditEntries.CountAsync(
            e => e.Outcome == AuditOutcome.Failure && (e.Action == "auth.admin.login" || e.Action == "auth.staff.login") && e.OccurredAtUtc >= since,
            cancellationToken).ConfigureAwait(false);

        return new DashboardOverviewResponse(
            counts.Sum(c => c.Count), Count(AccountStatus.Active), Count(AccountStatus.PendingActivation), Count(AccountStatus.Disabled), admins, failedLogins);
    }

    // ---------------------------------------------------------------- helpers

    private static ServiceError? RequireSuperAdmin(RequestContext context) =>
        context.Principal is { Type: PrincipalType.Admin, Role: AdminRole.SuperAdmin }
            ? null
            : ServiceError.Forbidden("Only a super administrator can manage administrator accounts.");

    private async Task<(AdminAccount? Admin, ServiceError? Error)> LoadAdminForChangeAsync(Guid id, RequestContext context, CancellationToken cancellationToken)
    {
        if (RequireSuperAdmin(context) is { } forbidden)
        {
            return (null, forbidden);
        }

        if (context.Principal!.Id == id)
        {
            return (null, ServiceError.Conflict("You cannot disable or reset your own account. Ask another super administrator."));
        }

        var admin = await db.Admins.FirstOrDefaultAsync(a => a.Id == id, cancellationToken).ConfigureAwait(false);
        if (admin is null)
        {
            return (null, ServiceError.NotFound("Administrator not found."));
        }

        if (admin is { Role: AdminRole.SuperAdmin, Status: AccountStatus.Active })
        {
            var otherActiveSuperAdmins = await db.Admins.CountAsync(
                a => a.Id != admin.Id && a.Role == AdminRole.SuperAdmin && a.Status == AccountStatus.Active && a.MfaEnabled, cancellationToken).ConfigureAwait(false);
            if (otherActiveSuperAdmins == 0)
            {
                return (null, ServiceError.Conflict("At least one active super administrator must remain."));
            }
        }

        return (admin, null);
    }

    private string IssueSetupCode(PrincipalType type, Guid accountId, RequestContext context, DateTimeOffset now)
    {
        var code = SecretCodes.NewSetupCode();
        db.SetupCodes.Add(new AccountSetupCode
        {
            Id = Guid.NewGuid(),
            AccountType = type,
            AccountId = accountId,
            CodeHash = SecretCodes.HashForStorage(SecretCodes.NormalizeSetupCode(code)),
            CreatedAtUtc = now,
            ExpiresAtUtc = now + _options.SetupCodeLifetime,
            CreatedByAdminId = context.Principal?.Id,
        });
        return code;
    }

    private async Task RevokeSetupCodesAsync(PrincipalType type, Guid accountId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var codes = await db.SetupCodes
            .Where(c => c.AccountType == type && c.AccountId == accountId && c.UsedAtUtc == null && c.RevokedAtUtc == null)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var code in codes)
        {
            code.RevokedAtUtc = now;
        }
    }

    private static StaffSummary ToSummary(StaffAccount s, DateTimeOffset now) =>
        new(s.Id, s.EmployeeCode, s.DisplayName, s.Department, s.Status.ToString(), s.CreatedAtUtc, s.LastLoginAtUtc, s.LockedUntilUtc > now);

    private static AdminSummary ToSummary(AdminAccount a) =>
        new(a.Id, a.Username, a.DisplayName, a.Role.ToString(), a.Status.ToString(), a.MfaEnabled, a.CreatedAtUtc, a.LastLoginAtUtc);
}
