using System.Net.Http.Json;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Client.Core;

/// <summary>Result of contacting the central server.</summary>
public sealed record ServerCheckResult(bool IsReachable, HealthResponse? Health, string? Error);

/// <summary>Typed client for the central server API.</summary>
public sealed class ServerClient(HttpClient http)
{
    public async Task<ServerCheckResult> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var health = await http.GetFromJsonAsync<HealthResponse>(ApiRoutes.Health, cancellationToken).ConfigureAwait(false);
            return health is null
                ? new ServerCheckResult(false, null, "Server returned an empty response.")
                : new ServerCheckResult(true, health, null);
        }
        catch (HttpRequestException ex)
        {
            return new ServerCheckResult(false, null, ex.Message);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new ServerCheckResult(false, null, "The server did not respond in time.");
        }
        catch (System.Text.Json.JsonException ex)
        {
            return new ServerCheckResult(false, null, "Unexpected response: " + ex.Message);
        }
    }

    public static ServerClient Create(Uri serverAddress, TimeSpan? timeout = null) =>
        new(new HttpClient { BaseAddress = serverAddress, Timeout = timeout ?? TimeSpan.FromSeconds(10) });
}
