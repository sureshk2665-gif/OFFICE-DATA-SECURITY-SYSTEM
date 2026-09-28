using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Policy;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>
/// Security policy definitions and the effective, signed policy of each computer. A computer uses its
/// assigned policy, or the default policy when none is assigned.
/// </summary>
public sealed class PolicyService(IServerDbContext db, AuditLog audit, IPolicySigningService signer, ExemptionService exemptions, TimeProvider clock)
{
    public const int MaxNameLength = 100;
    public const int MaxDescriptionLength = 500;
    public const string DefaultPolicyName = "Default policy";

    /// <summary>Creates the default policy on first start. All controls start switched off.</summary>
    public async Task EnsureDefaultPolicyAsync(CancellationToken cancellationToken = default)
    {
        if (await db.Policies.AnyAsync(p => p.IsDefault, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        db.Policies.Add(new PolicyDefinition
        {
            Id = Guid.NewGuid(),
            Name = DefaultPolicyName,
            Description = "Applies to every computer that has no other policy assigned.",
            IsDefault = true,
            SettingsJson = Serialize(new PolicySettings()),
            UpdatedAtUtc = clock.GetUtcNow(),
        });
        await audit.RecordAndSaveAsync(RequestContext.System, new AuditRecord("policy.create-default"), cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PolicySummary>> ListAsync(CancellationToken cancellationToken = default)
    {
        var policies = await db.Policies.AsNoTracking().OrderByDescending(p => p.IsDefault).ThenBy(p => p.Name)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var assigned = await db.Computers.AsNoTracking()
            .Where(c => c.Status == ComputerStatus.Trusted || c.Status == ComputerStatus.PendingApproval)
            .GroupBy(c => c.PolicyId)
            .Select(g => new { PolicyId = g.Key, Count = g.Count() })
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        return policies.Select(p => new PolicySummary(
            p.Id, p.Name, p.Description, p.IsDefault, p.Revision,
            assigned.Where(a => a.PolicyId == p.Id || (p.IsDefault && a.PolicyId == null)).Sum(a => a.Count),
            p.UpdatedAtUtc)).ToList();
    }

    public async Task<Result<PolicyDetail>> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var policy = await db.Policies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, cancellationToken).ConfigureAwait(false);
        return policy is null ? ServiceError.NotFound("Policy not found.") : ToDetail(policy);
    }

    public async Task<Result<PolicyDetail>> CreateAsync(SavePolicyRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (await ValidateAsync(request, null, cancellationToken).ConfigureAwait(false) is { } error)
        {
            return error;
        }

        var policy = new PolicyDefinition
        {
            Id = Guid.NewGuid(),
            Name = request.Name.Trim(),
            Description = AccountRules.CleanOptional(request.Description),
            SettingsJson = Serialize(request.Settings),
            UpdatedAtUtc = clock.GetUtcNow(),
            UpdatedByAdminId = context.Principal?.Id,
        };
        db.Policies.Add(policy);
        await audit.RecordAndSaveAsync(context, new AuditRecord("policy.create", TargetType: "Policy", TargetId: policy.Id.ToString(), Details: policy.Name), cancellationToken).ConfigureAwait(false);
        return ToDetail(policy);
    }

    public async Task<Result<PolicyDetail>> UpdateAsync(Guid id, SavePolicyRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var policy = await db.Policies.FirstOrDefaultAsync(p => p.Id == id, cancellationToken).ConfigureAwait(false);
        if (policy is null)
        {
            return ServiceError.NotFound("Policy not found.");
        }

        if (await ValidateAsync(request, id, cancellationToken).ConfigureAwait(false) is { } error)
        {
            return error;
        }

        policy.Name = request.Name.Trim();
        policy.Description = AccountRules.CleanOptional(request.Description);
        policy.SettingsJson = Serialize(request.Settings);
        policy.Revision++;
        policy.UpdatedAtUtc = clock.GetUtcNow();
        policy.UpdatedByAdminId = context.Principal?.Id;

        // Every computer using this policy gets a new, higher effective version.
        var affected = await db.Computers
            .Where(c => c.PolicyId == policy.Id || (policy.IsDefault && c.PolicyId == null))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var computer in affected)
        {
            computer.PolicyVersion++;
        }

        await audit.RecordAndSaveAsync(context, new AuditRecord("policy.update", TargetType: "Policy", TargetId: policy.Id.ToString(),
            Details: $"{policy.Name}, revision {policy.Revision}, {affected.Count} computer(s)"), cancellationToken).ConfigureAwait(false);
        return ToDetail(policy);
    }

    public async Task<Result<Done>> DeleteAsync(Guid id, RequestContext context, CancellationToken cancellationToken = default)
    {
        var policy = await db.Policies.FirstOrDefaultAsync(p => p.Id == id, cancellationToken).ConfigureAwait(false);
        if (policy is null)
        {
            return ServiceError.NotFound("Policy not found.");
        }

        if (policy.IsDefault)
        {
            return ServiceError.Conflict("The default policy cannot be deleted.");
        }

        if (await db.Computers.AnyAsync(c => c.PolicyId == id, cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.Conflict("This policy is assigned to computers. Assign them another policy first.");
        }

        db.Policies.Remove(policy);
        await audit.RecordAndSaveAsync(context, new AuditRecord("policy.delete", TargetType: "Policy", TargetId: id.ToString(), Details: policy.Name), cancellationToken).ConfigureAwait(false);
        return Done.Value;
    }

    /// <summary>The computer's effective policy, signed for the agent.</summary>
    public async Task<SignedPolicyEnvelope> GetSignedPolicyAsync(Computer computer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(computer);
        var settings = await GetEffectiveSettingsAsync(computer, cancellationToken).ConfigureAwait(false);
        var active = await exemptions.ForPolicyAsync(computer.Id, cancellationToken).ConfigureAwait(false);
        return signer.Sign(settings.ToDocument(computer.Id, computer.PolicyVersion, clock.GetUtcNow(), active));
    }

    public async Task<PolicySettings> GetEffectiveSettingsAsync(Computer computer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(computer);
        var policy = computer.PolicyId is { } policyId
            ? await db.Policies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == policyId, cancellationToken).ConfigureAwait(false)
            : null;
        policy ??= await db.Policies.AsNoTracking().FirstAsync(p => p.IsDefault, cancellationToken).ConfigureAwait(false);
        return Deserialize(policy.SettingsJson);
    }

    private async Task<ServiceError?> ValidateAsync(SavePolicyRequest request, Guid? existingId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > MaxNameLength)
        {
            return ServiceError.Validation($"Policy name is required and must be at most {MaxNameLength} characters.");
        }

        if (request.Description?.Trim().Length > MaxDescriptionLength)
        {
            return ServiceError.Validation($"Description must be at most {MaxDescriptionLength} characters.");
        }

        if (request.Settings is null)
        {
            return ServiceError.Validation("Policy settings are required.");
        }

        var errors = request.Settings.Validate();
        if (errors.Count > 0)
        {
            return ServiceError.Validation(string.Join(" ", errors));
        }

        var name = request.Name.Trim();
        if (await db.Policies.AnyAsync(p => p.Name == name && p.Id != existingId, cancellationToken).ConfigureAwait(false))
        {
            return ServiceError.Conflict($"A policy named '{name}' already exists.");
        }

        return null;
    }

    private static string Serialize(PolicySettings settings) => JsonSerializer.Serialize(settings, PolicySerializer.Options);

    private static PolicySettings Deserialize(string json) =>
        JsonSerializer.Deserialize<PolicySettings>(json, PolicySerializer.Options) ?? new PolicySettings();

    private static PolicyDetail ToDetail(PolicyDefinition p) =>
        new(p.Id, p.Name, p.Description, p.IsDefault, p.Revision, Deserialize(p.SettingsJson), p.UpdatedAtUtc);
}
