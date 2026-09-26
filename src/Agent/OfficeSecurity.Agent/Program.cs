using OfficeSecurity.Agent;
using OfficeSecurity.Agent.Enforcement;

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Services.AddWindowsService(options => options.ServiceName = "OfficeSecurityAgent");
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<EnforcementCoordinator>();
// Enforcers (IEnforcer) are registered here as they are implemented in Phase 5.
builder.Services.AddHostedService<AgentWorker>();

builder.Build().Run();
