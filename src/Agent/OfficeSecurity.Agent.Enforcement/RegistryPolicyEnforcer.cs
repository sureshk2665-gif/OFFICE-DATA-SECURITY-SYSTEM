using System.Globalization;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>What a control needs, derived from the policy.</summary>
public sealed record RegistryPlan(ControlState StateWhenApplied, string Detail, IReadOnlyList<PolicyValue> Values)
{
    public static RegistryPlan NotConfigured(string detail = "Not required by the policy.") => new(ControlState.NotConfigured, detail, []);
}

/// <summary>
/// A control implemented with documented Windows policy values. Reports <see cref="ControlState.Enforced"/>
/// (or the plan's state) only after reading every value back.
/// </summary>
public abstract class RegistryPolicyEnforcer(RegistryPolicyEngine engine, IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    public abstract SecurityControl Control { get; }

    /// <summary>A short name for events and messages, e.g. "USB drive blocking".</summary>
    protected abstract string Description { get; }

    protected abstract RegistryPlan Plan(SecurityPolicyDocument policy);

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var exemption = policy.Exceptions.FirstOrDefault(e => e.Control == Control && e.IsActiveAt(now));
        var plan = exemption is null ? Plan(policy) : RegistryPlan.NotConfigured();
        var result = engine.Apply(Control, plan.Values);

        if (result.Restored.Count > 0)
        {
            events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                $"{Description}: {result.Restored.Count} Windows setting(s) had been changed or removed outside this system and were restored: "
                + string.Join("; ", result.Restored.Select(v => $@"{v.Key}\{v.Name}")));
        }

        if (result.ReplacedForeign.Count > 0)
        {
            events.Raise(SecurityEventType.PolicyViolation, EventSeverities.Warning,
                $"{Description}: replaced {result.ReplacedForeign.Count} existing Windows setting(s) that had other values (for example from Group Policy): "
                + string.Join("; ", result.ReplacedForeign.Select(v => $@"{v.Key}\{v.Name}")));
        }

        return Task.FromResult(Status(plan, exemption, result.Mismatched, now));
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var now = clock.GetUtcNow();
        var exemption = policy.Exceptions.FirstOrDefault(e => e.Control == Control && e.IsActiveAt(now));
        var plan = exemption is null ? Plan(policy) : RegistryPlan.NotConfigured();
        return Task.FromResult(Status(plan, exemption, engine.Verify(plan.Values), now));
    }

    private ControlStatus Status(RegistryPlan plan, PolicyExemption? exemption, IReadOnlyList<PolicyValue> mismatched, DateTimeOffset now)
    {
        if (mismatched.Count > 0)
        {
            return new ControlStatus(Control, ControlState.Failed,
                "These Windows settings could not be applied: " + string.Join("; ", mismatched.Select(v => v.ToString())), now);
        }

        if (exemption is not null)
        {
            return new ControlStatus(Control, ControlState.TemporarilyAllowed,
                string.Create(CultureInfo.InvariantCulture, $"Temporarily allowed by an administrator until {exemption.ExpiresAtUtc:yyyy-MM-dd HH:mm} UTC: {exemption.Reason}"), now);
        }

        return Review(new ControlStatus(Control, plan.StateWhenApplied, plan.Detail, now));
    }

    /// <summary>Lets a control adjust its verified status with an additional check (e.g. the effective state).</summary>
    protected virtual ControlStatus Review(ControlStatus status) => status;
}
