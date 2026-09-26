using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Core;

/// <summary>The server rejected a request (with status), or could not be reached (no status).</summary>
public sealed class AgentServerException : Exception
{
    public AgentServerException()
    {
    }

    public AgentServerException(string message)
        : base(message)
    {
    }

    public AgentServerException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public AgentServerException(string message, HttpStatusCode? statusCode, Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode? StatusCode { get; }

    public bool IsUnreachable => StatusCode is null;
}

/// <summary>
/// HTTPS client used by the agent. The server certificate must chain to the pinned office CA; after
/// approval the agent authenticates with its own client certificate (mutual TLS).
/// </summary>
public sealed class AgentServerClient : IDisposable
{
    private readonly HttpClient _http;

    public AgentServerClient(HttpClient http)
    {
        _http = http;
    }

    public static AgentServerClient Create(Uri serverAddress, X509Certificate2 pinnedCa, X509Certificate2? clientCertificate)
    {
        ArgumentNullException.ThrowIfNull(pinnedCa);
        var ssl = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, certificate, _, errors) => ServerTrust.Validate(pinnedCa, certificate, errors),
        };
        if (clientCertificate is not null)
        {
            ssl.ClientCertificates = [clientCertificate];
            // Always offer the computer certificate, whatever issuer list the server advertises.
            ssl.LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate;
        }

        var handler = new SocketsHttpHandler { SslOptions = ssl, UseProxy = false, PooledConnectionLifetime = TimeSpan.FromMinutes(10) };
        return new AgentServerClient(new HttpClient(handler) { BaseAddress = serverAddress, Timeout = TimeSpan.FromSeconds(30) });
    }

    public void Dispose() => _http.Dispose();

    public Task<AgentEnrollResponse> EnrollAsync(AgentEnrollRequest request, CancellationToken ct) =>
        SendAsync<AgentEnrollResponse>(HttpMethod.Post, ApiRoutes.AgentEnroll, request, ct);

    public Task<AgentEnrollStatusResponse> GetEnrollmentStatusAsync(AgentEnrollStatusRequest request, CancellationToken ct) =>
        SendAsync<AgentEnrollStatusResponse>(HttpMethod.Post, ApiRoutes.AgentEnrollStatus, request, ct);

    public Task<AgentHeartbeatResponse> HeartbeatAsync(AgentHeartbeatRequest request, CancellationToken ct) =>
        SendAsync<AgentHeartbeatResponse>(HttpMethod.Post, ApiRoutes.AgentHeartbeat, request, ct);

    public Task<SignedPolicyEnvelope> GetPolicyAsync(CancellationToken ct) =>
        SendAsync<SignedPolicyEnvelope>(HttpMethod.Get, ApiRoutes.AgentPolicy, null, ct);

    public Task SendInventoryAsync(AgentInventoryRequest request, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Post, ApiRoutes.AgentInventory, request, ct);

    public Task<AgentEventsResponse> SendEventsAsync(AgentEventsRequest request, CancellationToken ct) =>
        SendAsync<AgentEventsResponse>(HttpMethod.Post, ApiRoutes.AgentEvents, request, ct);

    public Task<ComputerLoginTicketResponse> GetLoginTicketAsync(CancellationToken ct) =>
        SendAsync<ComputerLoginTicketResponse>(HttpMethod.Post, ApiRoutes.AgentLoginTicket, null, ct);

    private async Task<T> SendAsync<T>(HttpMethod method, string route, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, new Uri(route, UriKind.Relative));
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType());
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new AgentServerException("Server unreachable: " + ex.Message, null, ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new AgentServerException("Server did not respond in time.", null, ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var detail = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                throw new AgentServerException($"Server returned {(int)response.StatusCode}: {Truncate(detail)}", response.StatusCode);
            }

            if (typeof(T) == typeof(object) || response.StatusCode == HttpStatusCode.NoContent)
            {
                return default!;
            }

            return await response.Content.ReadFromJsonAsync<T>(ct).ConfigureAwait(false)
                   ?? throw new AgentServerException("Server returned an empty response.", response.StatusCode);
        }
    }

    private static string Truncate(string text) => text.Length <= 300 ? text : text[..300];
}
