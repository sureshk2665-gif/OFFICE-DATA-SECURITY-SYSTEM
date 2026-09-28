using OfficeSecurity.Server.Application.Reports;
using OfficeSecurity.Server.Application.Services;

namespace OfficeSecurity.Server.Api.Hosting;

/// <summary>
/// Regular server work: turning events and computer state into alerts (every 30 seconds by default) and saving
/// the weekly security summary. "Alerts:IntervalSeconds" = 0 switches it off (used by tests).
/// </summary>
internal sealed partial class ScheduledWorkService(IServiceScopeFactory scopes, IConfiguration configuration, TimeProvider clock, ILogger<ScheduledWorkService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var seconds = configuration.GetValue("Alerts:IntervalSeconds", 30);
        if (seconds <= 0)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var created = await scope.ServiceProvider.GetRequiredService<AlertEngine>().RunOnceAsync(stoppingToken);
                if (created > 0)
                {
                    LogAlerts(logger, created);
                }

                await scope.ServiceProvider.GetRequiredService<ScheduledReports>().RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
#pragma warning disable CA1031 // A failed run is logged and retried; the server keeps running.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                LogFailed(logger, ex);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(seconds), clock, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "{Count} new alert(s).")]
    private static partial void LogAlerts(ILogger logger, int count);

    [LoggerMessage(Level = LogLevel.Error, Message = "Scheduled work failed; retrying at the next interval.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
