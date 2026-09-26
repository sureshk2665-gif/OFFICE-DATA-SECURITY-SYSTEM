using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class AuthorizationTests
{
    /// <summary>The complete list of endpoints reachable without signing in. Adding one must be a deliberate change here.</summary>
    private static readonly HashSet<string> ExpectedAnonymous =
    [
        "GET " + ApiRoutes.Health,
        "GET " + ApiRoutes.CaCertificate,
        "GET " + ApiRoutes.SetupStatus,
        "POST " + ApiRoutes.SetupFirstAdmin,
        "POST " + ApiRoutes.AdminActivate,
        "POST " + ApiRoutes.AdminConfirmMfa,
        "POST " + ApiRoutes.AdminLogin,
        "POST " + ApiRoutes.AdminMfa,
        "POST " + ApiRoutes.StaffLogin,
        "POST " + ApiRoutes.StaffActivate,
    ];

    private static List<(string Method, string Route, bool Anonymous)> Endpoints(ServerFactory server)
    {
        _ = server.Services;
        return server.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .SelectMany(e => (e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? ["GET"])
                .Select(m => (m, "/" + e.RoutePattern.RawText!.TrimStart('/'), e.Metadata.GetMetadata<IAllowAnonymous>() is not null)))
            .ToList();
    }

    [Fact]
    public async Task Only_the_expected_endpoints_allow_anonymous_access()
    {
        await using var server = new ServerFactory();

        var anonymous = Endpoints(server).Where(e => e.Anonymous).Select(e => $"{e.Method} {e.Route}").ToHashSet();

        Assert.Equal(ExpectedAnonymous.Order(), anonymous.Order());
    }

    [Fact]
    public async Task Every_protected_endpoint_rejects_requests_without_a_session()
    {
        await using var server = new ServerFactory();
        using var client = server.Client();

        foreach (var (method, route, anonymous) in Endpoints(server).Where(e => !e.Anonymous))
        {
            var url = route.Replace("{id:guid}", Guid.NewGuid().ToString(), StringComparison.Ordinal);
            using var request = new HttpRequestMessage(new HttpMethod(method), url) { Content = JsonContent.Create(new { }) };
            var response = await client.SendAsync(request);
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{method} {route} returned {response.StatusCode}");
            _ = anonymous;
        }
    }

    [Fact]
    public async Task Staff_cannot_use_administrator_endpoints()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var (_, staffToken) = await server.CreateActiveStaffAsync(owner, "EMP100", "Staff member pass 2026");
        using var staff = server.Client(staffToken);

        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri(ApiRoutes.Staff, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri(ApiRoutes.Audit, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP101", "X", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.PostAsJsonAsync(ApiRoutes.Admins, new CreateAdminRequest("evil", "Evil", "SuperAdmin"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await staff.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
    }

    [Fact]
    public async Task Auditor_can_read_but_not_change()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor1", AdminRoles.Auditor);
        using var auditor = server.Client(auditorToken);

        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(new Uri(ApiRoutes.Staff, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(new Uri(ApiRoutes.Audit, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP200", "X", null))).StatusCode);
    }

    [Fact]
    public async Task Regular_admin_manages_staff_but_not_administrators()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var (adminToken, _) = await server.CreateAdminAsync(owner, "manager1", AdminRoles.Admin);
        using var admin = server.Client(adminToken);

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP300", "X", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PostAsJsonAsync(ApiRoutes.Admins, new CreateAdminRequest("other", "Other", "Admin"))).StatusCode);
    }

    [Fact]
    public async Task Super_admin_cannot_disable_self_or_remove_the_last_super_admin()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var client = server.Client(owner);
        var me = await client.GetFromJsonAsync<CurrentUserResponse>(ApiRoutes.Me);

        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync(new Uri(ApiRoutes.AdminDisable(me!.Id), UriKind.Relative), null)).StatusCode);

        var (secondToken, _) = await server.CreateAdminAsync(owner, "owner2", AdminRoles.SuperAdmin);
        using var second = server.Client(secondToken);
        Assert.Equal(HttpStatusCode.OK, (await second.PostAsync(new Uri(ApiRoutes.AdminDisable(me.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
    }
}
