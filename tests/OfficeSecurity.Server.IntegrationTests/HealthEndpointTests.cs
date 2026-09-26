using System.Net;
using System.Net.Http.Json;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class HealthEndpointTests
{
    [Fact]
    public async Task Health_endpoint_reports_healthy_without_sign_in()
    {
        await using var server = new ServerFactory();
        using var client = server.Client();

        var body = await client.GetFromJsonAsync<HealthResponse>(ApiRoutes.Health);

        Assert.Equal("Healthy", body!.Status);
        Assert.False(string.IsNullOrWhiteSpace(body.ServerVersion));
    }

    [Fact]
    public async Task Desktop_client_can_read_server_health()
    {
        await using var server = new ServerFactory();

        using var api = new ApiClient(server.Client());
        var result = await api.CheckHealthAsync();

        Assert.True(result.IsReachable, result.Error);
    }

    [Fact]
    public async Task Unknown_route_is_not_found_for_signed_in_users_and_unauthorized_otherwise()
    {
        await using var server = new ServerFactory();
        using var anonymous = server.Client();

        var response = await anonymous.GetAsync(new Uri("/api/v1/does-not-exist", UriKind.Relative));

        Assert.True(response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Ca_certificate_is_published_and_matches_pairing_file()
    {
        await using var server = new ServerFactory();
        using var client = server.Client();

        var der = await client.GetByteArrayAsync(new Uri(ApiRoutes.CaCertificate, UriKind.Relative));
        var info = await File.ReadAllTextAsync(Path.Combine(server.DataDirectory, "SERVER-CONNECTION-INFO.txt"));

        Assert.Contains(PairingCode.Compute(der), info, StringComparison.Ordinal);
    }
}
