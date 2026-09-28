using System.Reflection;
using Microsoft.Extensions.Hosting.WindowsServices;
using OfficeSecurity.Agent;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;

var command = args.Length > 0 ? args[0].ToLowerInvariant() : null;

// The Service Control Manager starts the agent with "service"; "run" is the same in a console window.
if (command is "service" or "run" || (command is null && WindowsServiceHelpers.IsWindowsService()))
{
    RunAgent(args);
    return 0;
}

return command switch
{
    "install" => await Commands.InstallAsync(args[1..]),
    "uninstall" => Commands.Uninstall(),
    "status" => await Commands.StatusAsync(),
    "inventory" => Commands.Inventory(),
    null or "help" or "--help" or "-h" or "/?" => Commands.Help(),
    _ => Commands.Help(args[0]),
};

static void RunAgent(string[] args)
{
    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
        Args = args.Length > 0 ? args[1..] : args,
        ContentRootPath = AppContext.BaseDirectory,
    });

    builder.Services.AddWindowsService(options => options.ServiceName = AgentPaths.ServiceName);

    var paths = new AgentPaths(builder.Configuration["Agent:DataDirectory"] is { Length: > 0 } dir ? dir : AgentPaths.DefaultDataDirectory());
    SecureDirectory.CreateAndProtect(paths.DataDirectory);

    builder.Services.AddSingleton(paths);
    builder.Services.AddSingleton(TimeProvider.System);
    builder.Services.AddSingleton(new AgentConfigStore(paths));
    builder.Services.AddSingleton<IDeviceKeyStore, CngDeviceKeyStore>();
    builder.Services.AddSingleton<IInventoryCollector, WindowsInventoryCollector>();
    builder.Services.AddSingleton(sp => new PendingEventStore(paths, sp.GetRequiredService<TimeProvider>()));

    // Security controls (Phase 5). Each one reports "Enforced" only after reading the Windows setting back.
    builder.Services.AddSingleton<IEnforcementEvents>(sp => new QueuedEnforcementEvents(sp.GetRequiredService<PendingEventStore>()));
    builder.Services.AddSingleton(new RegistryPolicyEngine(new WindowsPolicyRegistry(), new FileManagedSettingsStore(paths.DataDirectory)));
    builder.Services.AddSingleton<IEnforcer, RemovableStorageEnforcer>();
    builder.Services.AddSingleton<IEnforcer, MobileDeviceTransferEnforcer>();
    builder.Services.AddSingleton<IEnforcer, SoftwareInstallationEnforcer>();
    builder.Services.AddSingleton<IEnforcer, BrowserEnforcer>();
    builder.Services.AddSingleton<IEnforcer>(sp => new FirewallEnforcer(new WindowsFirewall(),
        new FileManagedSettingsStore(paths.DataDirectory, FileManagedSettingsStore.FirewallFile), sp.GetRequiredService<IEnforcementEvents>(), sp.GetRequiredService<TimeProvider>()));
    builder.Services.AddSingleton<IEnforcer>(sp => new ServiceProtectionEnforcer(sp.GetRequiredService<IEnforcementEvents>(), sp.GetRequiredService<TimeProvider>()));
    builder.Services.AddSingleton<EnforcementCoordinator>();
    builder.Services.AddSingleton(new PolicyCache(paths));
    builder.Services.AddSingleton(new AgentRuntimeOptions
    {
        AgentVersion = typeof(AgentWorker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.0.0",
    });
    builder.Services.AddSingleton<IInstallerVerifier, AuthenticodeInstallerVerifier>();
    builder.Services.AddSingleton<IInstallerRunner>(new ProcessInstallerRunner());
    builder.Services.AddSingleton(sp => new InstallationProcessor(paths, sp.GetRequiredService<IInstallerVerifier>(), sp.GetRequiredService<IInstallerRunner>(),
        sp.GetRequiredService<PendingEventStore>(), sp.GetRequiredService<ILogger<InstallationProcessor>>()));
    builder.Services.AddSingleton(sp => new AgentRuntime(
        sp.GetRequiredService<AgentConfigStore>(), sp.GetRequiredService<IDeviceKeyStore>(), sp.GetRequiredService<IInventoryCollector>(),
        sp.GetRequiredService<EnforcementCoordinator>(), sp.GetRequiredService<PendingEventStore>(), sp.GetRequiredService<PolicyCache>(),
        sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<ILogger<AgentRuntime>>(), sp.GetRequiredService<AgentRuntimeOptions>(),
        clientFactory: null, installations: sp.GetRequiredService<InstallationProcessor>()));
    builder.Services.AddSingleton<AgentLocalServer>(sp => new AgentLocalServer(sp.GetRequiredService<AgentRuntime>(), sp.GetRequiredService<ILogger<AgentLocalServer>>()));
    builder.Services.AddHostedService<AgentWorker>();

    builder.Build().Run();
}
