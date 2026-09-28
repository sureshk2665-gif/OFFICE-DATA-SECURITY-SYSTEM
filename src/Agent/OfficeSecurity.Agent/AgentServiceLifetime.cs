using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;

namespace OfficeSecurity.Agent;

/// <summary>
/// The Windows service lifetime, remembering whether Windows asked the service to stop because it is shutting
/// down (SERVICE_CONTROL_SHUTDOWN) rather than because someone stopped the service.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class AgentServiceLifetime(
    IHostEnvironment environment,
    IHostApplicationLifetime applicationLifetime,
    ILoggerFactory loggerFactory,
    IOptions<HostOptions> optionsAccessor,
    IOptions<WindowsServiceLifetimeOptions> windowsServiceOptionsAccessor)
    : WindowsServiceLifetime(environment, applicationLifetime, loggerFactory, optionsAccessor, windowsServiceOptionsAccessor)
{
    private static volatile bool _windowsShuttingDown;

    public static bool WindowsShuttingDown => _windowsShuttingDown;

    protected override void OnShutdown()
    {
        _windowsShuttingDown = true;
        base.OnShutdown();
    }
}
