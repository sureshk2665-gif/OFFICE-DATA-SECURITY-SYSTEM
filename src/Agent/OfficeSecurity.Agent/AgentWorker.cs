using OfficeSecurity.Agent.Core;

namespace OfficeSecurity.Agent;

/// <summary>Runs the agent loop and the local status pipe for as long as the service runs.</summary>
internal sealed partial class AgentWorker(AgentRuntime runtime, AgentLocalServer localServer, TimeProvider clock, ILogger<AgentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var pipe = localServer.RunAsync(stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            TimeSpan delay;
            try
            {
                delay = await runtime.RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // The service must keep running (and enforcing the cached policy) whatever goes wrong.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                LogUnexpected(logger, ex);
                delay = TimeSpan.FromMinutes(1);
            }

            try
            {
                await Task.Delay(delay, clock, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        await pipe;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        await runtime.NotifyStoppingAsync(AgentServiceLifetime.WindowsShuttingDown, TimeSpan.FromSeconds(5));
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Unexpected agent error; retrying in one minute.")]
    private static partial void LogUnexpected(ILogger logger, Exception exception);
}
