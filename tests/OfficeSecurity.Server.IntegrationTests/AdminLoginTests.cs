using System.Net;
using System.Net.Http.Json;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class AdminLoginTests
{
    [Fact]
    public async Task Login_requires_password_and_two_step_code()
    {
        await using var server = new ServerFactory();
        var secret = await server.BootstrapAdminAsync();
        using var client = server.Client();

        var wrongPassword = await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(ServerFactory.AdminUser, "not the password"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);

        server.NextTotpWindow();
        var ticket = await (await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(ServerFactory.AdminUser, ServerFactory.AdminPassword)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<AdminLoginResponse>();

        var wrongCode = await client.PostAsJsonAsync(ApiRoutes.AdminMfa, new AdminMfaRequest(ticket!.MfaTicket, "123456"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCode.StatusCode);

        var session = await (await client.PostAsJsonAsync(ApiRoutes.AdminMfa, new AdminMfaRequest(ticket.MfaTicket, server.CurrentTotp(secret))))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SessionResponse>();

        using var authed = server.Client(session!.Token);
        var me = await authed.GetFromJsonAsync<CurrentUserResponse>(ApiRoutes.Me);
        Assert.Equal(AccountTypes.Admin, me!.AccountType);
        Assert.Equal(AdminRoles.SuperAdmin, me.Role);
    }

    [Fact]
    public async Task Two_step_code_cannot_be_reused()
    {
        await using var server = new ServerFactory();
        var secret = await server.BootstrapAdminAsync();
        await server.LoginAdminAsync(ServerFactory.AdminUser, ServerFactory.AdminPassword, secret);
        using var client = server.Client();

        // Same 30-second window: the code just used must be rejected.
        var ticket = await (await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(ServerFactory.AdminUser, ServerFactory.AdminPassword)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<AdminLoginResponse>();
        var replay = await client.PostAsJsonAsync(ApiRoutes.AdminMfa, new AdminMfaRequest(ticket!.MfaTicket, server.CurrentTotp(secret)));

        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Account_locks_after_repeated_failures_and_unlocks_after_lockout_period()
    {
        await using var server = new ServerFactory();
        var secret = await server.BootstrapAdminAsync();
        using var client = server.Client();

        for (var i = 0; i < 5; i++)
        {
            await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(ServerFactory.AdminUser, "wrong password " + i));
        }

        var whileLocked = await client.PostAsJsonAsync(ApiRoutes.AdminLogin, new AdminLoginRequest(ServerFactory.AdminUser, ServerFactory.AdminPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, whileLocked.StatusCode);

        server.Clock.Advance(TimeSpan.FromMinutes(16));
        var token = await server.LoginAdminAsync(ServerFactory.AdminUser, ServerFactory.AdminPassword, secret);
        Assert.False(string.IsNullOrEmpty(token));
    }

    [Fact]
    public async Task Session_expires_after_idle_timeout()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var client = server.Client(owner);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
        server.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
    }

    [Fact]
    public async Task Logout_ends_the_session()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var client = server.Client(owner);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync(new Uri(ApiRoutes.Logout, UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
    }

    [Fact]
    public async Task Change_password_signs_out_other_sessions_and_new_password_works()
    {
        await using var server = new ServerFactory();
        var secret = await server.BootstrapAdminAsync();
        var first = await server.LoginAdminAsync(ServerFactory.AdminUser, ServerFactory.AdminPassword, secret);
        var second = await server.LoginAdminAsync(ServerFactory.AdminUser, ServerFactory.AdminPassword, secret);
        using var firstClient = server.Client(first);
        using var secondClient = server.Client(second);

        var wrongCurrent = await firstClient.PostAsJsonAsync(ApiRoutes.ChangePassword, new ChangePasswordRequest("not current", "Brand new password 99"));
        Assert.Equal(HttpStatusCode.BadRequest, wrongCurrent.StatusCode);

        var ok = await firstClient.PostAsJsonAsync(ApiRoutes.ChangePassword, new ChangePasswordRequest(ServerFactory.AdminPassword, "Brand new password 99"));
        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await firstClient.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await secondClient.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
        Assert.False(string.IsNullOrEmpty(await server.LoginAdminAsync(ServerFactory.AdminUser, "Brand new password 99", secret)));
    }
}
