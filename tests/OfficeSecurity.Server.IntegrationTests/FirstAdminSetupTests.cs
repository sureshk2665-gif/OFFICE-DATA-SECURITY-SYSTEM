using System.Net;
using System.Net.Http.Json;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class FirstAdminSetupTests
{
    [Fact]
    public async Task Fresh_server_requires_setup_and_accepts_only_the_generated_code()
    {
        await using var server = new ServerFactory();
        using var client = server.Client();

        Assert.True((await client.GetFromJsonAsync<SetupStatusResponse>(ApiRoutes.SetupStatus))!.FirstAdminSetupRequired);

        var wrong = await client.PostAsJsonAsync(ApiRoutes.SetupFirstAdmin,
            new FirstAdminSetupRequest("AAAA-BBBB-CCCC", ServerFactory.AdminUser, "Owner", ServerFactory.AdminPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        var weak = await client.PostAsJsonAsync(ApiRoutes.SetupFirstAdmin,
            new FirstAdminSetupRequest(server.ReadFirstAdminSetupCode(), ServerFactory.AdminUser, "Owner", "short"));
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
    }

    [Fact]
    public async Task Setup_completes_only_after_a_valid_authenticator_code()
    {
        await using var server = new ServerFactory();
        using var client = server.Client();

        var enrollment = await (await client.PostAsJsonAsync(ApiRoutes.SetupFirstAdmin,
                new FirstAdminSetupRequest(server.ReadFirstAdminSetupCode(), ServerFactory.AdminUser, "Owner", ServerFactory.AdminPassword)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<MfaEnrollmentResponse>();
        Assert.StartsWith("otpauth://totp/", enrollment!.OtpAuthUri, StringComparison.Ordinal);

        // Password alone is not enough before two-step verification is confirmed.
        var early = await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(ServerFactory.AdminUser, ServerFactory.AdminPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, early.StatusCode);

        var wrongCode = await client.PostAsJsonAsync(ApiRoutes.AdminConfirmMfa, new ConfirmMfaRequest(enrollment.EnrollmentTicket, "000000"));
        Assert.Equal(HttpStatusCode.BadRequest, wrongCode.StatusCode);

        var ok = await client.PostAsJsonAsync(ApiRoutes.AdminConfirmMfa, new ConfirmMfaRequest(enrollment.EnrollmentTicket, server.CurrentTotp(enrollment.SecretBase32)));
        Assert.True(ok.StatusCode == HttpStatusCode.NoContent, await ok.Content.ReadAsStringAsync());

        Assert.False((await client.GetFromJsonAsync<SetupStatusResponse>(ApiRoutes.SetupStatus))!.FirstAdminSetupRequired);
    }

    [Fact]
    public async Task Setup_cannot_be_repeated_once_an_administrator_exists()
    {
        await using var server = new ServerFactory();
        var usedCode = server.ReadFirstAdminSetupCode();
        await server.BootstrapAdminAsync();
        using var client = server.Client();

        var again = await client.PostAsJsonAsync(ApiRoutes.SetupFirstAdmin,
            new FirstAdminSetupRequest(usedCode, "intruder", "Intruder", "Intruder password 2026"));

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }
}
