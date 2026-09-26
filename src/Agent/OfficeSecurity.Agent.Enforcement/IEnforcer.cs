using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>
/// Applies one security control using a documented Windows mechanism and verifies the result by
/// reading back the effective operating-system state. Implementations must never report
/// <see cref="ControlState.Enforced"/> without that read-back.
/// </summary>
public interface IEnforcer
{
    SecurityControl Control { get; }

    /// <summary>Applies the policy, then verifies it. Must be idempotent.</summary>
    Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken);

    /// <summary>Verifies the currently effective state without changing anything.</summary>
    Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken);
}
