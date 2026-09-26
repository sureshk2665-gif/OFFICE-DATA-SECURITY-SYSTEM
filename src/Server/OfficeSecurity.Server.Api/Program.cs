using System.Reflection;
using OfficeSecurity.Contracts;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    // A Windows Service starts in System32; content root must be the install folder.
    ContentRootPath = AppContext.BaseDirectory,
});

// Runs as a Windows Service when started by the Service Control Manager; as a console app otherwise.
builder.Host.UseWindowsService(options => options.ServiceName = "OfficeSecurityServer");

builder.Services.AddProblemDetails();
builder.Services.AddSingleton(TimeProvider.System);

var app = builder.Build();

app.UseExceptionHandler();

var version = typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

app.MapGet(ApiRoutes.Health, (TimeProvider clock) =>
    TypedResults.Ok(new HealthResponse("Healthy", version, clock.GetUtcNow())));

app.Run();

/// <summary>Entry point marker for integration tests.</summary>
public partial class Program;
