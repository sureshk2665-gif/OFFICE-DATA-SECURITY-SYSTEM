using System.Net;
using System.Net.Sockets;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

/// <summary>Runs the server on real Kestrel HTTPS and connects the desktop client library to it.</summary>
public sealed class HttpsPairingTests
{
    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task<(ServerFactory Server, string PairingCode)> StartAsync()
    {
        var server = new ServerFactory { HttpsPort = FreePort() };
        server.UseKestrel();
        server.StartServer();
        var info = await File.ReadAllTextAsync(Path.Combine(server.DataDirectory, "SERVER-CONNECTION-INFO.txt"));
        var code = info.Split('\n').Single(l => l.StartsWith("Pairing code:", StringComparison.Ordinal))["Pairing code:".Length..].Trim();
        return (server, code);
    }

    [Fact]
    public async Task Client_pairs_with_correct_code_and_then_uses_pinned_https()
    {
        var (server, code) = await StartAsync();
        await using var _ = server;

        var result = await PairingService.PairAsync($"localhost:{server.HttpsPort}", code);

        Assert.True(result.Success, result.Error);
        using var api = ApiClient.FromSettings(result.Settings!);
        Assert.True((await api.CheckHealthAsync()).IsReachable);
        Assert.True((await api.GetSetupStatusAsync()).FirstAdminSetupRequired);
    }

    [Fact]
    public async Task Wrong_pairing_code_is_rejected()
    {
        var (server, _) = await StartAsync();
        await using var _ = server;

        var result = await PairingService.PairAsync($"localhost:{server.HttpsPort}", "0000-0000-0000-0000-0000");

        Assert.False(result.Success);
        Assert.Contains("does not match", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Client_pinned_to_another_server_refuses_to_connect()
    {
        var (serverA, codeA) = await StartAsync();
        var (serverB, _) = await StartAsync();
        await using var a = serverA;
        await using var b = serverB;

        var pairedWithA = (await PairingService.PairAsync($"localhost:{serverA.HttpsPort}", codeA)).Settings!;
        var pointedAtB = pairedWithA with { ServerAddress = $"https://localhost:{serverB.HttpsPort}" };

        using var api = ApiClient.FromSettings(pointedAtB);
        Assert.False((await api.CheckHealthAsync()).IsReachable);
        await Assert.ThrowsAsync<ApiException>(() => api.GetSetupStatusAsync());
    }

    [Fact]
    public async Task Address_not_covered_by_the_certificate_is_rejected()
    {
        var (server, code) = await StartAsync();
        await using var _ = server;

        var result = await PairingService.PairAsync($"127.0.0.2:{server.HttpsPort}", code);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task Complete_admin_and_staff_flow_through_the_client_library()
    {
        var (server, code) = await StartAsync();
        await using var _ = server;
        var settings = (await PairingService.PairAsync($"localhost:{server.HttpsPort}", code)).Settings!;
        using var api = ApiClient.FromSettings(settings);

        var enrollment = await api.SetupFirstAdminAsync(new FirstAdminSetupRequest(server.ReadFirstAdminSetupCode(), "owner", "Owner", ServerFactory.AdminPassword));
        await api.ConfirmMfaAsync(new ConfirmMfaRequest(enrollment.EnrollmentTicket, server.CurrentTotp(enrollment.SecretBase32)));

        server.NextTotpWindow();
        var ticket = await api.AdminLoginAsync(new AdminLoginRequest("owner", ServerFactory.AdminPassword));
        var admin = await api.AdminMfaAsync(new AdminMfaRequest(ticket.MfaTicket, server.CurrentTotp(enrollment.SecretBase32)));
        Assert.Equal(AdminRoles.SuperAdmin, admin.Role);

        var staffCode = await api.CreateStaffAsync(new CreateStaffRequest("EMP900", "Client Flow", "IT"));
        Assert.Equal(1, (await api.ListStaffAsync(1, 50, "client", null)).TotalCount);

        var failure = await Assert.ThrowsAsync<ApiException>(() => api.CreateStaffAsync(new CreateStaffRequest("EMP900", "Duplicate", null)));
        Assert.Equal(HttpStatusCode.Conflict, failure.StatusCode);
        Assert.Contains("already exists", failure.Message, StringComparison.Ordinal);

        using var staffApi = ApiClient.FromSettings(settings);
        var staff = await staffApi.StaffActivateAsync(new StaffActivateRequest("EMP900", staffCode.SetupCode, "Staff client password 1"));
        Assert.Equal("Client Flow", staff.DisplayName);

        var expired = false;
        staffApi.SessionExpired += (_, _) => expired = true;
        await api.DisableStaffAsync(staffCode.AccountId);
        await Assert.ThrowsAsync<ApiException>(() => staffApi.ChangePasswordAsync(new ChangePasswordRequest("Staff client password 1", "Another client password 2")));
        Assert.True(expired);
        Assert.False(staffApi.IsSignedIn);
    }
}
