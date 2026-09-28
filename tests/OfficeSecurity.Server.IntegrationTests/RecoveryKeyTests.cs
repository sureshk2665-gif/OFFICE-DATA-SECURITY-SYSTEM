using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class RecoveryKeyTests
{
    private const string Password = "123456-234567-345678-456789-567890-678901-789012-890123";
    private const string Protector = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";

    private static HttpClient AgentClient(ServerFactory server, AgentHarness agent) =>
        new(new CertificateHeaderHandler(X509Certificate2.CreateFromPem(agent.Config.Load().CertificatePem!)) { InnerHandler = server.Server.CreateHandler() })
        {
            BaseAddress = server.Server.BaseAddress,
        };

    private static Task<HttpResponseMessage> ReportAsync(HttpClient agent, params RecoveryKeyReport[] keys) =>
        agent.PostAsJsonAsync(ApiRoutes.AgentInventory, new AgentInventoryRequest(
            new HardwareInventory("PC-KEY", "Windows 11 Pro", "24H2", "26100", "Professional", null, null, null, null, null, null, true, false, "WORKGROUP"),
            [new ConnectedDevice(@"USBSTOR\DISK&VEN_X\1&0", "USB drive", "DiskDrive", "X", @"USB\VID_1&PID_2\1")], null, keys));

    [Fact]
    public async Task Recovery_keys_are_stored_encrypted_and_only_a_super_administrator_can_reveal_them()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        using var computer = AgentClient(server, agent);

        Assert.Equal(HttpStatusCode.NoContent, (await ReportAsync(computer,
            new RecoveryKeyReport("C:", Protector, Password),
            new RecoveryKeyReport("C:", "{bad}", "not-a-key"))).StatusCode); // malformed entries are ignored

        // Stored encrypted: the password is not in the database file.
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        var raw = await File.ReadAllTextAsync(server.DatabaseFile) + (File.Exists(server.DatabaseFile + "-wal") ? await ReadSharedAsync(server.DatabaseFile + "-wal") : string.Empty);
        Assert.DoesNotContain(Password, raw, StringComparison.Ordinal);

        var list = await admin.GetFromJsonAsync<List<RecoveryKeyResponse>>(ApiRoutes.ComputerRecoveryKeys(agent.ComputerId));
        var key = Assert.Single(list!);
        Assert.Equal("C:", key.Drive);

        var (adminToken, _) = await server.CreateAdminAsync(owner, "admin9", AdminRoles.Admin);
        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor9", AdminRoles.Auditor);
        using var plainAdmin = server.Client(adminToken);
        using var auditor = server.Client(auditorToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await plainAdmin.PostAsync(new Uri(ApiRoutes.ComputerRecoveryKeyReveal(agent.ComputerId, key.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsync(new Uri(ApiRoutes.ComputerRecoveryKeyReveal(agent.ComputerId, key.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync(new Uri(ApiRoutes.ComputerRecoveryKeyReveal(Guid.NewGuid(), key.Id), UriKind.Relative), null)).StatusCode);

        var revealed = await (await admin.PostAsync(new Uri(ApiRoutes.ComputerRecoveryKeyReveal(agent.ComputerId, key.Id), UriKind.Relative), null))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<RecoveryKeyRevealResponse>();
        Assert.Equal(Password, revealed!.RecoveryPassword);

        var audit = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        Assert.Contains(audit!.Items, a => a.Action == "bitlocker.recovery-key.reveal" && a.ActorName == "owner");
        Assert.Contains(audit.Items, a => a.Action == "bitlocker.recovery-key.stored");
        Assert.DoesNotContain(audit.Items, a => (a.Details ?? string.Empty).Contains(Password, StringComparison.Ordinal));

        // The USB drive's parent device is kept for approvals.
        var detail = await admin.GetFromJsonAsync<ComputerDetail>(ApiRoutes.ComputerById(agent.ComputerId));
        Assert.Equal(@"USB\VID_1&PID_2\1", Assert.Single(detail!.Devices).ParentInstanceId);
    }

    [Fact]
    public async Task Staff_cannot_see_recovery_keys()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var (_, staffToken) = await server.CreateActiveStaffAsync(owner, "EMP950", "Staff member pass 2026");
        using var staff = server.Client(staffToken);

        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri(ApiRoutes.ComputerRecoveryKeys(Guid.NewGuid()), UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.PostAsync(new Uri(ApiRoutes.ComputerRecoveryKeyReveal(Guid.NewGuid(), 1), UriKind.Relative), null)).StatusCode);
    }

    private static async Task<string> ReadSharedAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }
}
