using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Api.Endpoints;
using OfficeSecurity.Server.Api.Hosting;
using OfficeSecurity.Server.Api.Security;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Security;
using OfficeSecurity.Server.Application.Reports;
using OfficeSecurity.Server.Application.Services;
using OfficeSecurity.Server.Infrastructure.Certificates;
using OfficeSecurity.Server.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    // A Windows Service starts in System32; content root must be the install folder.
    ContentRootPath = AppContext.BaseDirectory,
});

// Runs as a Windows Service when started by the Service Control Manager; as a console app otherwise.
builder.Host.UseWindowsService(options => options.ServiceName = "OfficeSecurityServer");

// ---------------------------------------------------------------- data directory, secrets, certificates
var paths = new ServerPaths(builder.Configuration["Server:DataDirectory"] is { Length: > 0 } dir ? dir : ServerPaths.DefaultDataDirectory());
DataDirectoryProtection.CreateAndProtect(paths.DataDirectory);
var secretProtector = DataProtectionSecretProtector.Create(paths.KeysDirectory);
var certificates = new ServerCertificateAuthority(paths.CertificatesDirectory, secretProtector, TimeProvider.System)
    .LoadOrCreate(builder.Configuration.GetSection("Server:AdditionalHostNames").Get<string[]>());
var httpsPort = builder.Configuration.GetValue("Server:HttpsPort", 5443);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.ListenAnyIP(httpsPort, listen => listen.UseHttps(https =>
    {
        https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        // Agents present a client certificate (mutual TLS); people using the dashboard and staff app do not.
        // Certificates are validated by DeviceAuthenticationHandler against this server's own CA.
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        https.AllowAnyClientCertificate();
        https.ServerCertificate = X509CertificateLoader.LoadPkcs12(
            certificates.ServerCertificatePfx,
            password: null,
            // Windows SChannel cannot use ephemeral keys for a TLS server certificate.
            OperatingSystem.IsWindows() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet);
    }));
});

// ---------------------------------------------------------------- services
builder.Services.AddSingleton(paths);
builder.Services.AddSingleton(certificates);
builder.Services.AddSingleton<ISecretProtector>(secretProtector);
builder.Services.AddSingleton<DeviceCertificateAuthority>();
builder.Services.AddSingleton<IDeviceCertificateAuthority>(sp => sp.GetRequiredService<DeviceCertificateAuthority>());
builder.Services.AddSingleton<IPolicySigningService>(new PolicySigningService(paths.CertificatesDirectory, secretProtector));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection(SecurityOptions.SectionName));

builder.Services.AddDbContext<ServerDbContext>(options => options.UseSqlite(DatabaseInitializer.BuildConnectionString(paths.DatabaseFile)));
builder.Services.AddScoped<IServerDbContext>(sp => sp.GetRequiredService<ServerDbContext>());

builder.Services.AddSingleton(sp => new PasswordHasher(
    sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecurityOptions>>().Value.PasswordHashIterations));
builder.Services.AddSingleton<OneTimeTicketStore<AdminMfaTicket>>();
builder.Services.AddSingleton<OneTimeTicketStore<AdminEnrollmentTicket>>();
builder.Services.AddSingleton<OneTimeTicketStore<ComputerLoginTicket>>();
builder.Services.AddSingleton<AuditChainLock>();
builder.Services.AddScoped<AuditLog>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AccountAdministration>();
builder.Services.AddScoped<PolicyService>();
builder.Services.AddScoped<ExemptionService>();
builder.Services.AddScoped<RecoveryKeyService>();
builder.Services.AddScoped<ComputerAdministration>();
builder.Services.AddScoped<AgentService>();
builder.Services.AddScoped<SoftwareService>();
builder.Services.AddSingleton<AlertEngineLock>();
builder.Services.AddScoped<AlertEngine>();
builder.Services.AddScoped<AlertService>();
builder.Services.AddScoped<ReportService>();
builder.Services.AddSingleton(new SavedReportsOptions(paths.ReportsDirectory));
builder.Services.AddScoped<ScheduledReports>();
builder.Services.AddHostedService<ScheduledWorkService>();
builder.Services.AddSingleton<IPackageStorage>(new FilePackageStorage(paths.PackagesDirectory));

builder.Services.AddAuthentication(SessionAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, SessionAuthenticationHandler>(SessionAuthenticationHandler.SchemeName, null)
    .AddScheme<AuthenticationSchemeOptions, DeviceAuthenticationHandler>(DeviceAuthenticationHandler.SchemeName, null);
builder.Services.AddAuthorization(Policies.Configure);

var signInRequestsPerMinute = builder.Configuration.GetValue("Security:SignInRequestsPerMinute", 20);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(AuthEndpoints.SignInRateLimit, http => RateLimitPartition.GetFixedWindowLimiter(
        http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = signInRequestsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    // Pending agents poll for approval about once a minute; allow a whole office behind one address.
    options.AddPolicy(ComputerEndpoints.EnrollmentRateLimit, http => RateLimitPartition.GetFixedWindowLimiter(
        http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = signInRequestsPerMinute * 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// ---------------------------------------------------------------- endpoints
var version = typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

app.MapGet(ApiRoutes.Health, (TimeProvider clock) => TypedResults.Ok(new HealthResponse("Healthy", version, clock.GetUtcNow())))
    .AllowAnonymous();

// The CA certificate is public; clients verify it against the pairing code before trusting it.
app.MapGet(ApiRoutes.CaCertificate, (ServerCertificates certs) => TypedResults.Bytes(certs.CaCertificate.RawData, "application/pkix-cert"))
    .AllowAnonymous();

app.MapAuthEndpoints();
app.MapAdministrationEndpoints();
app.MapComputerEndpoints();
app.MapSoftwareEndpoints();
app.MapAlertEndpoints();
app.MapReportEndpoints();

await ServerStartup.InitializeAsync(app, certificates, httpsPort);
await app.RunAsync();

/// <summary>Entry point marker for integration tests.</summary>
public partial class Program;
