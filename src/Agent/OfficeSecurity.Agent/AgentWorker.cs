using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent;

/// <summary>
/// Main agent loop. Phase 1 scope: runs as a Windows Service and reports which controls are
/// implemented. Server communication and policy enforcement are added in Phases 3 and 5.
/// </summary>
internal sealed partial class AgentWorker(EnforcementCoordinator coordinator, ILogger<AgentWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        LogStarted(logger, Environment.MachineName);

        // No enrolled policy exists yet in Phase 1; verification uses an empty "unenrolled" policy.
        var policy = UnenrolledPolicy.Create();

        using var timer = new PeriodicTimer(Interval);
        do
        {
            var statuses = await coordinator.VerifyAsync(policy, stoppingToken);
            foreach (var status in statuses)
            {
                LogControlStatus(logger, status.Control, status.State, status.Details);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Office Security Agent started on {MachineName} (development build: not enrolled, no enforcement).")]
    private static partial void LogStarted(ILogger logger, string machineName);

    [LoggerMessage(Level = LogLevel.Information, Message = "Control {Control}: {State} {Details}")]
    private static partial void LogControlStatus(ILogger logger, SecurityControl control, ControlState state, string? details);
}
