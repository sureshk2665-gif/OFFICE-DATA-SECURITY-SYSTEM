using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.UnitTests;

public sealed class EnforcementCoordinatorTests
{
    private static readonly SecurityPolicyDocument Policy = new()
    {
        Version = 1,
        ComputerId = Guid.NewGuid(),
        IssuedAtUtc = DateTimeOffset.UtcNow,
    };

    [Fact]
    public async Task Every_control_without_an_enforcer_is_reported_as_not_implemented()
    {
        var coordinator = new EnforcementCoordinator([], TimeProvider.System);

        var statuses = await coordinator.VerifyAsync(Policy, CancellationToken.None);

        Assert.Equal(Enum.GetValues<SecurityControl>().Length, statuses.Count);
        Assert.All(statuses, s => Assert.Equal(ControlState.NotImplemented, s.State));
    }

    [Fact]
    public async Task Enforcer_result_is_reported_for_its_control()
    {
        var enforcer = new FakeEnforcer(SecurityControl.RemovableStorage, ControlState.Enforced);
        var coordinator = new EnforcementCoordinator([enforcer], TimeProvider.System);

        var statuses = await coordinator.ApplyAsync(Policy, CancellationToken.None);

        Assert.Equal(ControlState.Enforced, statuses.Single(s => s.Control == SecurityControl.RemovableStorage).State);
        Assert.Equal(1, enforcer.ApplyCalls);
    }

    [Fact]
    public async Task Failing_enforcer_is_reported_as_failed_and_does_not_stop_others()
    {
        var failing = new FakeEnforcer(SecurityControl.ApplicationControl, ControlState.Enforced, throwOnRun: true);
        var working = new FakeEnforcer(SecurityControl.RemovableStorage, ControlState.Enforced);
        var coordinator = new EnforcementCoordinator([failing, working], TimeProvider.System);

        var statuses = await coordinator.ApplyAsync(Policy, CancellationToken.None);

        var failed = statuses.Single(s => s.Control == SecurityControl.ApplicationControl);
        Assert.Equal(ControlState.Failed, failed.State);
        Assert.Contains("simulated", failed.Details, StringComparison.Ordinal);
        Assert.Equal(ControlState.Enforced, statuses.Single(s => s.Control == SecurityControl.RemovableStorage).State);
    }

    [Fact]
    public async Task Cancellation_is_propagated()
    {
        var coordinator = new EnforcementCoordinator([], TimeProvider.System);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() => coordinator.VerifyAsync(Policy, cts.Token));
    }

    private sealed class FakeEnforcer(SecurityControl control, ControlState state, bool throwOnRun = false) : IEnforcer
    {
        public int ApplyCalls { get; private set; }

        public SecurityControl Control => control;

        public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
        {
            ApplyCalls++;
            return VerifyAsync(policy, cancellationToken);
        }

        public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken) =>
            throwOnRun
                ? throw new InvalidOperationException("simulated failure")
                : Task.FromResult(new ControlStatus(control, state, null, DateTimeOffset.UtcNow));
    }
}
