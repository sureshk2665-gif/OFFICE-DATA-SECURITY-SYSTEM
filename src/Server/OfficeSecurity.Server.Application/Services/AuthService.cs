using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Security;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Ticket issued after a correct admin password, redeemed with a two-step code.</summary>
public sealed record AdminMfaTicket(Guid AdminId);

/// <summary>Ticket issued while an admin adds the authenticator app, redeemed with the first code.</summary>
public sealed record AdminEnrollmentTicket(Guid AdminId);

/// <summary>
/// Sign-in, account activation, sessions and password changes for administrators and staff.
/// Failure messages are deliberately generic; the precise reason is written to the audit log.
/// </summary>
public sealed class AuthService(
    IServerDbContext db,
    AuditLog audit,
    PasswordHasher hasher,
    ISecretProtector protector,
    OneTimeTicketStore<AdminMfaTicket> mfaTickets,
    OneTimeTicketStore<AdminEnrollmentTicket> enrollmentTickets,
    IOptions<SecurityOptions> options,
    TimeProvider clock)
{
    private readonly SecurityOptions _options = options.Value;

    private string SignInFailedMessage =>
        $"Sign-in failed. Check your details and try again. After {_options.MaxFailedAttempts} failed attempts the account is locked for {_options.LockoutDuration.TotalMinutes:0} minutes.";

    // ---------------------------------------------------------------- first administrator

    public async Task<bool> IsFirstAdminSetupRequiredAsync(CancellationToken cancellationToken = default) =>
        !await db.Admins.AnyAsync(a => a.Status == AccountStatus.Active && a.MfaEnabled, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// When no administrator exists yet, replaces any previous bootstrap code with a new one and returns it
    /// so the server host can show it to the person installing the server. Returns <c>null</c> otherwise.
    /// </summary>
    public async Task<string?> IssueFirstAdminSetupCodeIfRequiredAsync(CancellationToken cancellationToken = default)
    {
        if (!await IsFirstAdminSetupRequiredAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var now = clock.GetUtcNow();
        var previous = await db.SetupCodes
            .Where(c => c.AccountType == PrincipalType.Admin && c.AccountId == Guid.Empty && c.UsedAtUtc == null && c.RevokedAtUtc == null)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var code in previous)
        {
            code.RevokedAtUtc = now;
        }

        var setupCode = SecretCodes.NewSetupCode();
        db.SetupCodes.Add(new AccountSetupCode
        {
            Id = Guid.NewGuid(),
            AccountType = PrincipalType.Admin,
            AccountId = Guid.Empty,
            CodeHash = SecretCodes.HashForStorage(SecretCodes.NormalizeSetupCode(setupCode)),
            CreatedAtUtc = now,
            ExpiresAtUtc = now.AddDays(30),
        });
        await audit.RecordAndSaveAsync(RequestContext.System, new AuditRecord("setup.first-admin.code-issued"), cancellationToken).ConfigureAwait(false);
        return setupCode;
    }

    public async Task<Result<MfaEnrollmentResponse>> CreateFirstAdminAsync(FirstAdminSetupRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!await IsFirstAdminSetupRequiredAsync(cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.Conflict("The first administrator has already been set up.");
        }

        var now = clock.GetUtcNow();
        var codeHash = SecretCodes.HashForStorage(SecretCodes.NormalizeSetupCode(request.SetupCode));
        var bootstrapCode = await db.SetupCodes
            .FirstOrDefaultAsync(c => c.AccountType == PrincipalType.Admin && c.AccountId == Guid.Empty && c.CodeHash == codeHash, cancellationToken)
            .ConfigureAwait(false);
        if (bootstrapCode is null || !bootstrapCode.IsUsableAt(now))
        {
            await audit.RecordAndSaveAsync(context, new AuditRecord("setup.first-admin", AuditOutcome.Failure, Details: "invalid setup code"), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized("The setup code is not valid. Use the code shown by the server (it changes each time the server starts).");
        }

        var error = AccountRules.ValidateUsername(request.Username)
                    ?? AccountRules.ValidateDisplayName(request.DisplayName)
                    ?? PasswordPolicy.Validate(request.Password, request.Username);
        if (error is not null)
        {
            return ServiceError.Validation(error);
        }

        // Only unfinished accounts from an earlier, abandoned first-time setup can exist at this point.
        var leftovers = await db.Admins.ToListAsync(cancellationToken).ConfigureAwait(false);
        db.Admins.RemoveRange(leftovers);

        var secret = Totp.GenerateSecret();
        var admin = new AdminAccount
        {
            Id = Guid.NewGuid(),
            Username = request.Username.Trim(),
            NormalizedUsername = AccountRules.Normalize(request.Username),
            DisplayName = request.DisplayName.Trim(),
            Role = AdminRole.SuperAdmin,
            Status = AccountStatus.PendingActivation,
            PasswordHash = hasher.Hash(request.Password),
            TotpSecretProtected = protector.Protect(secret),
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
        };
        db.Admins.Add(admin);
        bootstrapCode.UsedAtUtc = now;

        await audit.RecordAndSaveAsync(context, new AuditRecord("setup.first-admin", TargetType: "Admin", TargetId: admin.Id.ToString(), ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
        return BeginEnrollment(admin, secret);
    }

    // ---------------------------------------------------------------- administrator activation & sign-in

    public async Task<Result<MfaEnrollmentResponse>> ActivateAdminAsync(AdminActivateRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = AccountRules.Normalize(request.Username ?? string.Empty);
        var admin = await db.Admins.FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();

        if (admin is null || admin.Status != AccountStatus.PendingActivation || IsLocked(admin, now))
        {
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.activate", AuditOutcome.Failure,
                TargetType: "Admin", TargetId: admin?.Id.ToString(), Details: admin is null ? "unknown account" : IsLocked(admin, now) ? "locked" : "not pending activation",
                ActorNameOverride: Truncate(request.Username)), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized("The user name or setup code is not valid, or the account is locked.");
        }

        var code = await FindUsableSetupCodeAsync(PrincipalType.Admin, admin.Id, request.SetupCode, now, cancellationToken).ConfigureAwait(false);
        if (code is null)
        {
            RegisterFailure(admin, now);
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.activate", AuditOutcome.Failure,
                TargetType: "Admin", TargetId: admin.Id.ToString(), Details: "invalid setup code", ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized("The user name or setup code is not valid, or the account is locked.");
        }

        var passwordError = PasswordPolicy.Validate(request.NewPassword, admin.Username);
        if (passwordError is not null)
        {
            return ServiceError.Validation(passwordError);
        }

        var secret = Totp.GenerateSecret();
        admin.PasswordHash = hasher.Hash(request.NewPassword);
        admin.TotpSecretProtected = protector.Protect(secret);
        admin.MfaEnabled = false;
        admin.LastTotpTimeStep = 0;
        admin.FailedLoginCount = 0;
        admin.LockedUntilUtc = null;
        admin.UpdatedAtUtc = now;
        code.UsedAtUtc = now;

        await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.activate", TargetType: "Admin", TargetId: admin.Id.ToString(), ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
        return BeginEnrollment(admin, secret);
    }

    public async Task<Result<Done>> ConfirmAdminMfaAsync(ConfirmMfaRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!enrollmentTickets.TryPeek(request.EnrollmentTicket, out var ticket))
        {
            return ServiceError.Unauthorized("The setup session has expired. Start the setup again.");
        }

        var admin = await db.Admins.FirstOrDefaultAsync(a => a.Id == ticket.AdminId, cancellationToken).ConfigureAwait(false);
        if (admin is null || admin.Status != AccountStatus.PendingActivation || admin.TotpSecretProtected is null)
        {
            enrollmentTickets.Consume(request.EnrollmentTicket);
            return ServiceError.Unauthorized("The setup session is no longer valid. Start the setup again.");
        }

        var now = clock.GetUtcNow();
        var step = Totp.Verify(protector.Unprotect(admin.TotpSecretProtected), request.Code, now, lastUsedTimeStep: 0);
        if (step is null)
        {
            enrollmentTickets.RecordFailedAttempt(request.EnrollmentTicket);
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.mfa-enroll", AuditOutcome.Failure,
                TargetType: "Admin", TargetId: admin.Id.ToString(), Details: "wrong code", ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
            return ServiceError.Validation("The code is not correct. Check that the phone's clock is right and enter the current 6-digit code.");
        }

        admin.MfaEnabled = true;
        admin.Status = AccountStatus.Active;
        admin.LastTotpTimeStep = step.Value;
        admin.UpdatedAtUtc = now;
        enrollmentTickets.Consume(request.EnrollmentTicket);

        await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.mfa-enroll", TargetType: "Admin", TargetId: admin.Id.ToString(), ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
        return Done.Value;
    }

    public async Task<Result<AdminLoginResponse>> AdminLoginAsync(AdminLoginRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = AccountRules.Normalize(request.Username ?? string.Empty);
        var admin = await db.Admins.FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();

        string? failure = admin switch
        {
            null => "unknown account",
            _ when IsLocked(admin, now) => "locked",
            { Status: not AccountStatus.Active } => $"account {admin.Status}",
            { MfaEnabled: false } => "two-step verification not set up",
            _ => null,
        };

        var passwordOk = hasher.Verify(request.Password ?? string.Empty, failure is null ? admin!.PasswordHash : null);
        if (failure is null && !passwordOk)
        {
            failure = "wrong password";
            RegisterFailure(admin!, now);
        }

        if (failure is not null)
        {
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.login", AuditOutcome.Failure,
                TargetType: "Admin", TargetId: admin?.Id.ToString(), Details: failure,
                ActorTypeOverride: AuditActorType.Anonymous, ActorNameOverride: Truncate(request.Username)), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized(SignInFailedMessage);
        }

        if (hasher.NeedsRehash(admin!.PasswordHash!))
        {
            admin.PasswordHash = hasher.Hash(request.Password!);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return new AdminLoginResponse(mfaTickets.Issue(new AdminMfaTicket(admin.Id), _options.MfaTicketLifetime));
    }

    public async Task<Result<SessionResponse>> AdminMfaAsync(AdminMfaRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!mfaTickets.TryPeek(request.MfaTicket, out var ticket))
        {
            return ServiceError.Unauthorized("The sign-in has expired. Enter your user name and password again.");
        }

        var admin = await db.Admins.FirstOrDefaultAsync(a => a.Id == ticket.AdminId, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        if (admin is null || admin.Status != AccountStatus.Active || !admin.MfaEnabled || admin.TotpSecretProtected is null || IsLocked(admin, now))
        {
            mfaTickets.Consume(request.MfaTicket);
            return ServiceError.Unauthorized(SignInFailedMessage);
        }

        var step = Totp.Verify(protector.Unprotect(admin.TotpSecretProtected), request.Code, now, admin.LastTotpTimeStep);
        if (step is null)
        {
            mfaTickets.RecordFailedAttempt(request.MfaTicket);
            RegisterFailure(admin, now);
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.login", AuditOutcome.Failure,
                TargetType: "Admin", TargetId: admin.Id.ToString(), Details: "wrong two-step code",
                ActorTypeOverride: AuditActorType.Anonymous, ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized("The code is not correct or has already been used. Wait for a new code and try again.");
        }

        mfaTickets.Consume(request.MfaTicket);
        admin.LastTotpTimeStep = step.Value;
        admin.FailedLoginCount = 0;
        admin.LockedUntilUtc = null;
        admin.LastLoginAtUtc = now;

        var (token, session) = NewSession(PrincipalType.Admin, admin.Id, context, now);
        await audit.RecordAndSaveAsync(context, new AuditRecord("auth.admin.login", TargetType: "Admin", TargetId: admin.Id.ToString(),
            ActorTypeOverride: AuditActorType.Admin, ActorIdOverride: admin.Id, ActorNameOverride: admin.Username), cancellationToken).ConfigureAwait(false);
        return new SessionResponse(token, session.ExpiresAtUtc, ToUser(admin));
    }

    // ---------------------------------------------------------------- staff activation & sign-in

    public async Task<Result<SessionResponse>> StaffActivateAsync(StaffActivateRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = AccountRules.Normalize(request.EmployeeCode ?? string.Empty);
        var staff = await db.Staff.FirstOrDefaultAsync(s => s.NormalizedEmployeeCode == normalized, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        const string Generic = "The employee code or setup code is not valid, or the account is locked. Ask your administrator for a new setup code.";

        if (staff is null || staff.Status != AccountStatus.PendingActivation || IsLocked(staff, now))
        {
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.staff.activate", AuditOutcome.Failure,
                TargetType: "Staff", TargetId: staff?.Id.ToString(), Details: staff is null ? "unknown account" : IsLocked(staff, now) ? "locked" : $"account {staff.Status}",
                ActorTypeOverride: AuditActorType.Anonymous, ActorNameOverride: Truncate(request.EmployeeCode)), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized(Generic);
        }

        var code = await FindUsableSetupCodeAsync(PrincipalType.Staff, staff.Id, request.SetupCode, now, cancellationToken).ConfigureAwait(false);
        if (code is null)
        {
            RegisterFailure(staff, now);
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.staff.activate", AuditOutcome.Failure,
                TargetType: "Staff", TargetId: staff.Id.ToString(), Details: "invalid setup code",
                ActorTypeOverride: AuditActorType.Anonymous, ActorNameOverride: staff.EmployeeCode), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized(Generic);
        }

        var passwordError = PasswordPolicy.Validate(request.NewPassword, staff.EmployeeCode);
        if (passwordError is not null)
        {
            return ServiceError.Validation(passwordError);
        }

        staff.PasswordHash = hasher.Hash(request.NewPassword);
        staff.Status = AccountStatus.Active;
        staff.FailedLoginCount = 0;
        staff.LockedUntilUtc = null;
        staff.UpdatedAtUtc = now;
        staff.LastLoginAtUtc = now;
        code.UsedAtUtc = now;

        var (token, session) = NewSession(PrincipalType.Staff, staff.Id, context, now);
        await audit.RecordAndSaveAsync(context, new AuditRecord("auth.staff.activate", TargetType: "Staff", TargetId: staff.Id.ToString(),
            ActorTypeOverride: AuditActorType.Staff, ActorIdOverride: staff.Id, ActorNameOverride: staff.EmployeeCode), cancellationToken).ConfigureAwait(false);
        return new SessionResponse(token, session.ExpiresAtUtc, ToUser(staff));
    }

    public async Task<Result<SessionResponse>> StaffLoginAsync(StaffLoginRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = AccountRules.Normalize(request.EmployeeCode ?? string.Empty);
        var staff = await db.Staff.FirstOrDefaultAsync(s => s.NormalizedEmployeeCode == normalized, cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();

        string? failure = staff switch
        {
            null => "unknown account",
            _ when IsLocked(staff, now) => "locked",
            { Status: not AccountStatus.Active } => $"account {staff.Status}",
            _ => null,
        };

        var passwordOk = hasher.Verify(request.Password ?? string.Empty, failure is null ? staff!.PasswordHash : null);
        if (failure is null && !passwordOk)
        {
            failure = "wrong password";
            RegisterFailure(staff!, now);
        }

        if (failure is not null)
        {
            await audit.RecordAndSaveAsync(context, new AuditRecord("auth.staff.login", AuditOutcome.Failure,
                TargetType: "Staff", TargetId: staff?.Id.ToString(), Details: failure,
                ActorTypeOverride: AuditActorType.Anonymous, ActorNameOverride: Truncate(request.EmployeeCode)), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized(staff?.Status == AccountStatus.PendingActivation
                ? "This account has not been activated yet. Use \"First sign-in\" with the setup code from your administrator."
                : SignInFailedMessage);
        }

        if (hasher.NeedsRehash(staff!.PasswordHash!))
        {
            staff.PasswordHash = hasher.Hash(request.Password!);
        }

        staff.FailedLoginCount = 0;
        staff.LockedUntilUtc = null;
        staff.LastLoginAtUtc = now;
        var (token, session) = NewSession(PrincipalType.Staff, staff.Id, context, now);
        await audit.RecordAndSaveAsync(context, new AuditRecord("auth.staff.login", TargetType: "Staff", TargetId: staff.Id.ToString(),
            ActorTypeOverride: AuditActorType.Staff, ActorIdOverride: staff.Id, ActorNameOverride: staff.EmployeeCode), cancellationToken).ConfigureAwait(false);
        return new SessionResponse(token, session.ExpiresAtUtc, ToUser(staff));
    }

    // ---------------------------------------------------------------- sessions

    /// <summary>Resolves a bearer token to the signed-in principal, or <c>null</c> if it is not (or no longer) valid.</summary>
    public async Task<CurrentPrincipal?> ValidateSessionAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 128)
        {
            return null;
        }

        var hash = SecretCodes.HashForStorage(token);
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.TokenHash == hash && s.EndedAtUtc == null, cancellationToken).ConfigureAwait(false);
        if (session is null)
        {
            return null;
        }

        var now = clock.GetUtcNow();
        var idleTimeout = session.PrincipalType == PrincipalType.Admin ? _options.AdminSessionIdleTimeout : _options.StaffSessionIdleTimeout;
        if (now >= session.ExpiresAtUtc || now - session.LastSeenAtUtc >= idleTimeout)
        {
            session.EndedAtUtc = now;
            session.EndReason = now >= session.ExpiresAtUtc ? "expired" : "idle timeout";
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }

        CurrentPrincipal? principal = null;
        if (session.PrincipalType == PrincipalType.Admin)
        {
            var admin = await db.Admins.AsNoTracking().FirstOrDefaultAsync(a => a.Id == session.PrincipalId, cancellationToken).ConfigureAwait(false);
            if (admin is { Status: AccountStatus.Active })
            {
                principal = new CurrentPrincipal(PrincipalType.Admin, admin.Id, admin.Username, admin.DisplayName, admin.Role, session.Id);
            }
        }
        else
        {
            var staff = await db.Staff.AsNoTracking().FirstOrDefaultAsync(s => s.Id == session.PrincipalId, cancellationToken).ConfigureAwait(false);
            if (staff is { Status: AccountStatus.Active })
            {
                principal = new CurrentPrincipal(PrincipalType.Staff, staff.Id, staff.EmployeeCode, staff.DisplayName, null, session.Id);
            }
        }

        if (principal is null)
        {
            session.EndedAtUtc = now;
            session.EndReason = "account not active";
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }

        // Limit writes: the idle timer only needs minute precision.
        if (now - session.LastSeenAtUtc >= TimeSpan.FromMinutes(1))
        {
            session.LastSeenAtUtc = now;
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return principal;
    }

    public async Task LogoutAsync(RequestContext context, CancellationToken cancellationToken = default)
    {
        var principal = context.Principal ?? throw new InvalidOperationException("Logout requires a signed-in principal.");
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.Id == principal.SessionId, cancellationToken).ConfigureAwait(false);
        if (session is { EndedAtUtc: null })
        {
            session.EndedAtUtc = clock.GetUtcNow();
            session.EndReason = "logout";
        }

        await audit.RecordAndSaveAsync(context, new AuditRecord(principal.Type == PrincipalType.Admin ? "auth.admin.logout" : "auth.staff.logout",
            TargetType: principal.Type.ToString(), TargetId: principal.Id.ToString()), cancellationToken).ConfigureAwait(false);
    }

    public async Task<Result<Done>> ChangePasswordAsync(ChangePasswordRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var principal = context.Principal ?? throw new InvalidOperationException("Changing a password requires a signed-in principal.");
        var now = clock.GetUtcNow();

        ILockableAccount account;
        string? currentHash;
        if (principal.Type == PrincipalType.Admin)
        {
            var admin = await db.Admins.FirstAsync(a => a.Id == principal.Id, cancellationToken).ConfigureAwait(false);
            (account, currentHash) = (admin, admin.PasswordHash);
        }
        else
        {
            var staff = await db.Staff.FirstAsync(s => s.Id == principal.Id, cancellationToken).ConfigureAwait(false);
            (account, currentHash) = (staff, staff.PasswordHash);
        }

        var action = principal.Type == PrincipalType.Admin ? "auth.admin.change-password" : "auth.staff.change-password";
        if (!hasher.Verify(request.CurrentPassword ?? string.Empty, currentHash))
        {
            RegisterFailure(account, now);
            await audit.RecordAndSaveAsync(context, new AuditRecord(action, AuditOutcome.Failure, principal.Type.ToString(), principal.Id.ToString(), "wrong current password"), cancellationToken).ConfigureAwait(false);
            return ServiceError.Validation("The current password is not correct.");
        }

        var error = PasswordPolicy.Validate(request.NewPassword, principal.LoginName);
        if (error is not null)
        {
            return ServiceError.Validation(error);
        }

        if (string.Equals(request.CurrentPassword, request.NewPassword, StringComparison.Ordinal))
        {
            return ServiceError.Validation("The new password must be different from the current password.");
        }

        var newHash = hasher.Hash(request.NewPassword);
        if (account is AdminAccount a)
        {
            a.PasswordHash = newHash;
            a.UpdatedAtUtc = now;
        }
        else if (account is StaffAccount s)
        {
            s.PasswordHash = newHash;
            s.UpdatedAtUtc = now;
        }

        account.FailedLoginCount = 0;
        await EndSessionsAsync(principal.Type, principal.Id, now, "password changed", exceptSessionId: principal.SessionId, cancellationToken).ConfigureAwait(false);
        await audit.RecordAndSaveAsync(context, new AuditRecord(action, TargetType: principal.Type.ToString(), TargetId: principal.Id.ToString()), cancellationToken).ConfigureAwait(false);
        return Done.Value;
    }

    public static CurrentUserResponse ToUser(CurrentPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return new CurrentUserResponse(principal.Id, principal.Type == PrincipalType.Admin ? AccountTypes.Admin : AccountTypes.Staff,
            principal.LoginName, principal.DisplayName, principal.Role?.ToString());
    }

    // ---------------------------------------------------------------- helpers shared with AccountAdministration

    internal async Task EndSessionsAsync(PrincipalType type, Guid principalId, DateTimeOffset now, string reason, Guid? exceptSessionId, CancellationToken cancellationToken)
    {
        var sessions = await db.Sessions
            .Where(s => s.PrincipalType == type && s.PrincipalId == principalId && s.EndedAtUtc == null)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var session in sessions.Where(s => s.Id != exceptSessionId))
        {
            session.EndedAtUtc = now;
            session.EndReason = reason;
        }
    }

    private MfaEnrollmentResponse BeginEnrollment(AdminAccount admin, byte[] secret)
    {
        var secretBase32 = Base32.Encode(secret);
        var ticket = enrollmentTickets.Issue(new AdminEnrollmentTicket(admin.Id), _options.MfaEnrollmentLifetime);
        return new MfaEnrollmentResponse(ticket, secretBase32, Totp.BuildOtpAuthUri(_options.TotpIssuer, admin.Username, secretBase32));
    }

    private async Task<AccountSetupCode?> FindUsableSetupCodeAsync(PrincipalType type, Guid accountId, string? code, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var hash = SecretCodes.HashForStorage(SecretCodes.NormalizeSetupCode(code));
        var match = await db.SetupCodes
            .FirstOrDefaultAsync(c => c.AccountType == type && c.AccountId == accountId && c.CodeHash == hash, cancellationToken)
            .ConfigureAwait(false);
        return match is not null && match.IsUsableAt(now) ? match : null;
    }

    private (string Token, Session Session) NewSession(PrincipalType type, Guid principalId, RequestContext context, DateTimeOffset now)
    {
        var token = SecretCodes.NewToken();
        var session = new Session
        {
            Id = Guid.NewGuid(),
            TokenHash = SecretCodes.HashForStorage(token),
            PrincipalType = type,
            PrincipalId = principalId,
            CreatedAtUtc = now,
            LastSeenAtUtc = now,
            ExpiresAtUtc = now + (type == PrincipalType.Admin ? _options.AdminSessionLifetime : _options.StaffSessionLifetime),
            SourceIp = context.SourceIp,
        };
        db.Sessions.Add(session);
        return (token, session);
    }

    private static bool IsLocked(ILockableAccount account, DateTimeOffset now) => account.LockedUntilUtc is { } until && until > now;

    private void RegisterFailure(ILockableAccount account, DateTimeOffset now)
    {
        account.FailedLoginCount++;
        if (account.FailedLoginCount >= _options.MaxFailedAttempts)
        {
            account.LockedUntilUtc = now + _options.LockoutDuration;
            account.FailedLoginCount = 0;
        }
    }

    private static CurrentUserResponse ToUser(AdminAccount admin) =>
        new(admin.Id, AccountTypes.Admin, admin.Username, admin.DisplayName, admin.Role.ToString());

    private static CurrentUserResponse ToUser(StaffAccount staff) =>
        new(staff.Id, AccountTypes.Staff, staff.EmployeeCode, staff.DisplayName, null);

    // The attempted login name is recorded only if it looks like a login name; a password typed into the
    // wrong field must not end up in the audit log.
    private static string? Truncate(string? value) =>
        value is null ? null
        : AccountRules.ValidateUsername(value) is null || AccountRules.ValidateEmployeeCode(value) is null ? value.Trim()
        : "(invalid login name)";
}
