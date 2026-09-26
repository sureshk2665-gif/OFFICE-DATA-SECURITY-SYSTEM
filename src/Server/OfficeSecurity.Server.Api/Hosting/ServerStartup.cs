using System.Globalization;
using System.Text;
using OfficeSecurity.Contracts;
using OfficeSecurity.Server.Application.Services;
using OfficeSecurity.Server.Infrastructure.Certificates;
using OfficeSecurity.Server.Infrastructure.Persistence;

namespace OfficeSecurity.Server.Api.Hosting;

/// <summary>One-time work when the server starts: database migration and first-administrator bootstrap.</summary>
internal static partial class ServerStartup
{
    public static async Task InitializeAsync(WebApplication app, ServerCertificates certificates, int httpsPort)
    {
        var paths = app.Services.GetRequiredService<ServerPaths>();
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("OfficeSecurity.Server.Startup");

        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ServerDbContext>();
        await DatabaseInitializer.InitializeAsync(db);

        var pairingCode = PairingCode.Compute(certificates.CaCertificate.RawData);
        var addresses = certificates.ServerNames
            .Where(n => n != "::1")
            .Select(n => string.Create(CultureInfo.InvariantCulture, $"https://{n}:{httpsPort}"))
            .ToList();
        WriteConnectionInfo(paths, pairingCode, addresses);
        LogConnectionInfo(logger, string.Join(Environment.NewLine + "    ", addresses), pairingCode, paths.ConnectionInfoFile);

        var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
        var setupCode = await auth.IssueFirstAdminSetupCodeIfRequiredAsync();
        if (setupCode is null)
        {
            File.Delete(paths.FirstAdminSetupCodeFile);
            return;
        }

        await File.WriteAllTextAsync(paths.FirstAdminSetupCodeFile,
            "OFFICE SECURITY SERVER - FIRST ADMINISTRATOR SETUP CODE" + Environment.NewLine + Environment.NewLine +
            setupCode + Environment.NewLine + Environment.NewLine +
            "Enter this code in the Administrator Dashboard to create the first administrator." + Environment.NewLine +
            "A new code is generated every time the server starts until setup is complete." + Environment.NewLine +
            "This file is deleted automatically once setup is complete." + Environment.NewLine);
        LogSetupCode(logger, setupCode, paths.FirstAdminSetupCodeFile);
    }

    private static void WriteConnectionInfo(ServerPaths paths, string pairingCode, IReadOnlyList<string> addresses)
    {
        var text = new StringBuilder()
            .AppendLine("OFFICE SECURITY SERVER - CONNECTION INFORMATION")
            .AppendLine()
            .AppendLine("Server addresses (use the one that other office computers can reach):")
            .AppendJoin(Environment.NewLine, addresses.Select(a => "  " + a)).AppendLine()
            .AppendLine()
            .AppendLine("Pairing code: " + pairingCode)
            .AppendLine()
            .AppendLine("The dashboard and staff application ask for the address and pairing code the first time they connect.")
            .AppendLine("The pairing code proves they are talking to this server. It is not a password.");
        File.WriteAllText(paths.ConnectionInfoFile, text.ToString());
    }

    [LoggerMessage(Level = LogLevel.Warning, Message =
        "\n==================== OFFICE SECURITY SERVER ====================\n  Addresses:\n    {Addresses}\n  Pairing code: {PairingCode}\n  (also saved in {File})\n================================================================")]
    private static partial void LogConnectionInfo(ILogger logger, string addresses, string pairingCode, string file);

    [LoggerMessage(Level = LogLevel.Warning, Message =
        "\n================== FIRST-TIME SETUP REQUIRED ==================\n  No administrator exists yet.\n  First administrator setup code: {SetupCode}\n  (also saved in {File})\n================================================================")]
    private static partial void LogSetupCode(ILogger logger, string setupCode, string file);
}
