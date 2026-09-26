using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Client.Core;

/// <summary>Result of contacting the central server.</summary>
public sealed record ServerCheckResult(bool IsReachable, HealthResponse? Health, string? Error);

/// <summary>An error from the server, with a message suitable to show to the user.</summary>
public sealed class ApiException : Exception
{
    public ApiException()
    {
    }

    public ApiException(string message)
        : base(message)
    {
    }

    public ApiException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ApiException(string message, HttpStatusCode? statusCode, Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode? StatusCode { get; }
}

/// <summary>Typed client for the central server API over pinned HTTPS.</summary>
public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;

    public ApiClient(Uri serverAddress, X509Certificate2 pinnedCa)
        : this(new HttpClient(ServerTrust.CreatePinnedHandler(pinnedCa)) { BaseAddress = serverAddress, Timeout = TimeSpan.FromSeconds(20) })
    {
    }

    /// <summary>For tests and advanced hosting: uses the given client as-is.</summary>
    public ApiClient(HttpClient http)
    {
        _http = http;
    }

    /// <summary>Raised when the server rejects the session (expired, signed out elsewhere, or account disabled).</summary>
    public event EventHandler? SessionExpired;

    public string? Token { get; private set; }

    public CurrentUserResponse? CurrentUser { get; private set; }

    public bool IsSignedIn => Token is not null;

    public static ApiClient FromSettings(ClientSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.IsPaired || !ClientSettings.TryParseServerAddress(settings.ServerAddress, out var address))
        {
            throw new InvalidOperationException("The client is not connected to a server yet.");
        }

        using var ca = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(settings.CaCertificateBase64!));
        return new ApiClient(address!, X509CertificateLoader.LoadCertificate(ca.RawData));
    }

    public void Dispose() => _http.Dispose();

    // ---------------------------------------------------------------- anonymous

    public async Task<ServerCheckResult> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var health = await _http.GetFromJsonAsync<HealthResponse>(ApiRoutes.Health, cancellationToken).ConfigureAwait(false);
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
        catch (JsonException ex)
        {
            return new ServerCheckResult(false, null, "Unexpected response: " + ex.Message);
        }
    }

    public Task<SetupStatusResponse> GetSetupStatusAsync(CancellationToken ct = default) =>
        SendAsync<SetupStatusResponse>(HttpMethod.Get, ApiRoutes.SetupStatus, null, ct);

    public Task<MfaEnrollmentResponse> SetupFirstAdminAsync(FirstAdminSetupRequest request, CancellationToken ct = default) =>
        SendAsync<MfaEnrollmentResponse>(HttpMethod.Post, ApiRoutes.SetupFirstAdmin, request, ct);

    public Task<MfaEnrollmentResponse> ActivateAdminAsync(AdminActivateRequest request, CancellationToken ct = default) =>
        SendAsync<MfaEnrollmentResponse>(HttpMethod.Post, ApiRoutes.AdminActivate, request, ct);

    public Task ConfirmMfaAsync(ConfirmMfaRequest request, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Post, ApiRoutes.AdminConfirmMfa, request, ct);

    public Task<AdminLoginResponse> AdminLoginAsync(AdminLoginRequest request, CancellationToken ct = default) =>
        SendAsync<AdminLoginResponse>(HttpMethod.Post, ApiRoutes.AdminLogin, request, ct);

    public async Task<CurrentUserResponse> AdminMfaAsync(AdminMfaRequest request, CancellationToken ct = default) =>
        StartSession(await SendAsync<SessionResponse>(HttpMethod.Post, ApiRoutes.AdminMfa, request, ct).ConfigureAwait(false));

    public async Task<CurrentUserResponse> StaffLoginAsync(StaffLoginRequest request, CancellationToken ct = default) =>
        StartSession(await SendAsync<SessionResponse>(HttpMethod.Post, ApiRoutes.StaffLogin, request, ct).ConfigureAwait(false));

    public async Task<CurrentUserResponse> StaffActivateAsync(StaffActivateRequest request, CancellationToken ct = default) =>
        StartSession(await SendAsync<SessionResponse>(HttpMethod.Post, ApiRoutes.StaffActivate, request, ct).ConfigureAwait(false));

    // ---------------------------------------------------------------- signed in

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        try
        {
            if (Token is not null)
            {
                await SendAsync<object>(HttpMethod.Post, ApiRoutes.Logout, null, ct).ConfigureAwait(false);
            }
        }
        catch (ApiException)
        {
            // Signing out locally must always succeed, even if the server cannot be reached.
        }
        finally
        {
            Token = null;
            CurrentUser = null;
        }
    }

    public Task ChangePasswordAsync(ChangePasswordRequest request, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Post, ApiRoutes.ChangePassword, request, ct);

    public Task<DashboardOverviewResponse> GetOverviewAsync(CancellationToken ct = default) =>
        SendAsync<DashboardOverviewResponse>(HttpMethod.Get, ApiRoutes.DashboardOverview, null, ct);

    public Task<PagedResult<StaffSummary>> ListStaffAsync(int page, int pageSize, string? search, string? status, CancellationToken ct = default) =>
        SendAsync<PagedResult<StaffSummary>>(HttpMethod.Get, ApiRoutes.Staff + Query(("page", page), ("pageSize", pageSize), ("search", search), ("status", status)), null, ct);

    public Task<SetupCodeResponse> CreateStaffAsync(CreateStaffRequest request, CancellationToken ct = default) =>
        SendAsync<SetupCodeResponse>(HttpMethod.Post, ApiRoutes.Staff, request, ct);

    public Task<StaffSummary> UpdateStaffAsync(Guid id, UpdateStaffRequest request, CancellationToken ct = default) =>
        SendAsync<StaffSummary>(HttpMethod.Put, ApiRoutes.StaffById(id), request, ct);

    public Task<StaffSummary> DisableStaffAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<StaffSummary>(HttpMethod.Post, ApiRoutes.StaffDisable(id), null, ct);

    public Task<StaffSummary> EnableStaffAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<StaffSummary>(HttpMethod.Post, ApiRoutes.StaffEnable(id), null, ct);

    public Task<SetupCodeResponse> ResetStaffAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<SetupCodeResponse>(HttpMethod.Post, ApiRoutes.StaffResetSetupCode(id), null, ct);

    public Task<List<AdminSummary>> ListAdminsAsync(CancellationToken ct = default) =>
        SendAsync<List<AdminSummary>>(HttpMethod.Get, ApiRoutes.Admins, null, ct);

    public Task<SetupCodeResponse> CreateAdminAsync(CreateAdminRequest request, CancellationToken ct = default) =>
        SendAsync<SetupCodeResponse>(HttpMethod.Post, ApiRoutes.Admins, request, ct);

    public Task<AdminSummary> DisableAdminAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<AdminSummary>(HttpMethod.Post, ApiRoutes.AdminDisable(id), null, ct);

    public Task<AdminSummary> EnableAdminAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<AdminSummary>(HttpMethod.Post, ApiRoutes.AdminEnable(id), null, ct);

    public Task<SetupCodeResponse> ResetAdminAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<SetupCodeResponse>(HttpMethod.Post, ApiRoutes.AdminResetSetupCode(id), null, ct);

    public Task<PagedResult<AuditEntryResponse>> ListAuditAsync(int page, int pageSize, string? search, CancellationToken ct = default) =>
        SendAsync<PagedResult<AuditEntryResponse>>(HttpMethod.Get, ApiRoutes.Audit + Query(("page", page), ("pageSize", pageSize), ("search", search)), null, ct);

    public Task<AuditVerificationResponse> VerifyAuditAsync(CancellationToken ct = default) =>
        SendAsync<AuditVerificationResponse>(HttpMethod.Get, ApiRoutes.AuditVerify, null, ct);

    // ---------------------------------------------------------------- plumbing

    private CurrentUserResponse StartSession(SessionResponse session)
    {
        Token = session.Token;
        CurrentUser = session.User;
        return session.User;
    }

    private async Task<T> SendAsync<T>(HttpMethod method, string route, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, new Uri(route, UriKind.Relative));
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType());
        }

        var authenticated = Token is not null;
        if (authenticated)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new ApiException("Cannot reach the office security server. Check the network connection and that the server is running.", null, ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new ApiException("The office security server did not respond in time. Try again.", null, ex);
        }

        using (response)
        {
            if (response.IsSuccessStatusCode)
            {
                if (response.StatusCode == HttpStatusCode.NoContent || typeof(T) == typeof(object))
                {
                    return default!;
                }

                return await response.Content.ReadFromJsonAsync<T>(ct).ConfigureAwait(false)
                       ?? throw new ApiException("The server returned an empty response.", response.StatusCode);
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized && authenticated)
            {
                Token = null;
                CurrentUser = null;
                SessionExpired?.Invoke(this, EventArgs.Empty);
                throw new ApiException("Your session has ended. Please sign in again.", response.StatusCode);
            }

            throw new ApiException(await ReadErrorAsync(response, ct).ConfigureAwait(false), response.StatusCode);
        }
    }

    private static async Task<string> ReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        switch (response.StatusCode)
        {
            case HttpStatusCode.TooManyRequests:
                return "Too many attempts. Wait a minute and try again.";
            case HttpStatusCode.Forbidden:
                return "Your account is not allowed to do this.";
        }

        try
        {
            using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false), cancellationToken: ct).ConfigureAwait(false);
            if (doc.RootElement.TryGetProperty("detail", out var detail) && detail.GetString() is { Length: > 0 } message)
            {
                return message;
            }
        }
        catch (JsonException)
        {
            // Fall through to the generic message.
        }

        return string.Create(CultureInfo.InvariantCulture, $"The server reported an error ({(int)response.StatusCode}).");
    }

    private static string Query(params (string Name, object? Value)[] parameters)
    {
        var parts = parameters
            .Where(p => p.Value is not null && !(p.Value is string s && string.IsNullOrWhiteSpace(s)))
            .Select(p => $"{p.Name}={Uri.EscapeDataString(Convert.ToString(p.Value, CultureInfo.InvariantCulture)!)}");
        var query = string.Join('&', parts);
        return query.Length == 0 ? string.Empty : "?" + query;
    }
}
