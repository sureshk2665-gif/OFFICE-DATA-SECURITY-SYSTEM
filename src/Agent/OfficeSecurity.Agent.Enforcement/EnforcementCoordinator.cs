using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Enforcement;

/// <summary>
/// Runs every registered enforcer and produces one status per <see cref="SecurityControl"/>.
/// Controls without an enforcer are reported as <see cref="ControlState.NotImplemented"/> so the
/// dashboard never shows a control as active when it is not.
/// </summary>
public sealed class EnforcementCoordinator
{
    private readonly Dictionary<SecurityControl, IEnforcer> _enforcers;
    private readonly TimeProvider _clock;

    public EnforcementCoordinator(IEnumerable<IEnforcer> enforcers, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(enforcers);
        _enforcers = enforcers.ToDictionary(e => e.Control);
        _clock = clock;
    }

    public Task<IReadOnlyList<ControlStatus>> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken) =>
        RunAsync(policy, (e, p, ct) => e.ApplyAsync(p, ct), cancellationToken);

    public Task<IReadOnlyList<ControlStatus>> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken) =>
        RunAsync(policy, (e, p, ct) => e.VerifyAsync(p, ct), cancellationToken);

    private async Task<IReadOnlyList<ControlStatus>> RunAsync(
        SecurityPolicyDocument policy,
        Func<IEnforcer, SecurityPolicyDocument, CancellationToken, Task<ControlStatus>> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var results = new List<ControlStatus>();

        foreach (var control in Enum.GetValues<SecurityControl>())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!_enforcers.TryGetValue(control, out var enforcer))
            {
                results.Add(new ControlStatus(control, ControlState.NotImplemented, "Not implemented in this agent version.", _clock.GetUtcNow()));
                continue;
            }

            try
            {
                results.Add(await action(enforcer, policy, cancellationToken).ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
#pragma warning disable CA1031 // One failing control must not stop the others from being enforced.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                results.Add(new ControlStatus(control, ControlState.Failed, ex.Message, _clock.GetUtcNow()));
            }
        }

        return results;
    }
}
