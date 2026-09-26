using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Security;

namespace OfficeSecurity.Server.IntegrationTests;

/// <summary>Runs the real server in memory with its own data directory and a controllable clock.</summary>
public sealed partial class ServerFactory : WebApplicationFactory<Program>
{
    public const string AdminUser = "owner";
    public const string AdminPassword = "Blue harbour lantern 2026!";

    public string DataDirectory { get; } = Path.Combine(Path.GetTempPath(), "ocss-it-" + Guid.NewGuid().ToString("N"));

    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    public int HttpsPort { get; init; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Server:DataDirectory", DataDirectory);
        builder.UseSetting("Server:HttpsPort", HttpsPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
        builder.UseSetting("Security:PasswordHashIterations", "1000");
        builder.UseSetting("Security:SignInRequestsPerMinute", "100000");
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Clock);
            services.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter, TestClientCertificateFilter>();
        });
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(DataDirectory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort cleanup of the temporary directory.
        }
    }

    public string DatabaseFile => Path.Combine(DataDirectory, "office-security.db");

    /// <summary>True after <see cref="StartRealHttps"/>: requests go over real TLS to Kestrel.</summary>
    public bool RealTls { get; private set; }

    public void StartRealHttps()
    {
        UseKestrel();
        StartServer();
        RealTls = true;
    }

    public HttpClient Client(string? token = null)
    {
        var client = RealTls
            ? new HttpClient(OfficeSecurity.Client.Core.ServerTrust.CreatePinnedHandler(
                System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(Path.Combine(DataDirectory, "certificates", "office-security-ca.cer"))))
            {
                BaseAddress = new Uri($"https://localhost:{HttpsPort}"),
            }
            : CreateClient();
        if (token is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return client;
    }

    public string ReadFirstAdminSetupCode()
    {
        _ = Services; // ensures the server has started
        var text = File.ReadAllText(Path.Combine(DataDirectory, "FIRST-ADMIN-SETUP-CODE.txt"));
        return SetupCodeRegex().Match(text).Value;
    }

    public string CurrentTotp(string secretBase32) =>
        Totp.ComputeCode(Base32.Decode(secretBase32), Totp.GetTimeStep(Clock.GetUtcNow()));

    /// <summary>Moves to the next 30-second window so a new, unused two-step code is available.</summary>
    public void NextTotpWindow() => Clock.Advance(TimeSpan.FromSeconds(Totp.StepSeconds));

    /// <summary>Creates and activates the first super administrator; returns the authenticator secret.</summary>
    public async Task<string> BootstrapAdminAsync()
    {
        using var client = Client();
        var enrollment = await (await client.PostAsJsonAsync(ApiRoutes.SetupFirstAdmin,
                new FirstAdminSetupRequest(ReadFirstAdminSetupCode(), AdminUser, "Office Owner", AdminPassword)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<MfaEnrollmentResponse>();
        (await client.PostAsJsonAsync(ApiRoutes.AdminConfirmMfa, new ConfirmMfaRequest(enrollment!.EnrollmentTicket, CurrentTotp(enrollment.SecretBase32))))
            .EnsureSuccessStatusCode();
        return enrollment.SecretBase32;
    }

    public async Task<string> LoginAdminAsync(string username, string password, string secretBase32)
    {
        NextTotpWindow();
        using var client = Client();
        var step1 = await (await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(username, password)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<AdminLoginResponse>();
        var session = await (await client.PostAsJsonAsync(ApiRoutes.AdminMfa, new AdminMfaRequest(step1!.MfaTicket, CurrentTotp(secretBase32))))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SessionResponse>();
        return session!.Token;
    }

    /// <summary>Bootstraps the owner account and returns a signed-in super administrator token.</summary>
    public async Task<string> OwnerTokenAsync()
    {
        var secret = await BootstrapAdminAsync();
        return await LoginAdminAsync(AdminUser, AdminPassword, secret);
    }

    /// <summary>Creates an administrator with the given role, activates it and returns (token, secret).</summary>
    public async Task<(string Token, string Secret)> CreateAdminAsync(string ownerToken, string username, string role)
    {
        using var owner = Client(ownerToken);
        var code = await (await owner.PostAsJsonAsync(ApiRoutes.Admins, new CreateAdminRequest(username, username, role)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SetupCodeResponse>();

        using var anonymous = Client();
        const string Password = "Second admin password 77";
        var enrollment = await (await anonymous.PostAsJsonAsync(ApiRoutes.AdminActivate, new AdminActivateRequest(username, code!.SetupCode, Password)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<MfaEnrollmentResponse>();
        (await anonymous.PostAsJsonAsync(ApiRoutes.AdminConfirmMfa, new ConfirmMfaRequest(enrollment!.EnrollmentTicket, CurrentTotp(enrollment.SecretBase32))))
            .EnsureSuccessStatusCode();
        return (await LoginAdminAsync(username, Password, enrollment.SecretBase32), enrollment.SecretBase32);
    }

    /// <summary>Creates a staff account and activates it with the given password; returns (id, token).</summary>
    public async Task<(Guid Id, string Token)> CreateActiveStaffAsync(string adminToken, string employeeCode, string password)
    {
        using var admin = Client(adminToken);
        var code = await (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest(employeeCode, "Staff " + employeeCode, "Accounts")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SetupCodeResponse>();
        using var anonymous = Client();
        var session = await (await anonymous.PostAsJsonAsync(ApiRoutes.StaffActivate, new StaffActivateRequest(employeeCode, code!.SetupCode, password)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SessionResponse>();
        return (code.AccountId, session!.Token);
    }

    public string PairingCodeFromConnectionInfo()
    {
        _ = Services;
        var info = File.ReadAllText(Path.Combine(DataDirectory, "SERVER-CONNECTION-INFO.txt"));
        return info.Split('\n').Single(l => l.StartsWith("Pairing code:", StringComparison.Ordinal))["Pairing code:".Length..].Trim();
    }

    public async Task<string> CreateEnrollmentCodeAsync(string adminToken)
    {
        using var admin = Client(adminToken);
        var response = await (await admin.PostAsync(new Uri(ApiRoutes.EnrollmentCodes, UriKind.Relative), null))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<EnrollmentCodeResponse>();
        return response!.EnrollmentCode;
    }

    [GeneratedRegex("[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}")]
    private static partial Regex SetupCodeRegex();
}
