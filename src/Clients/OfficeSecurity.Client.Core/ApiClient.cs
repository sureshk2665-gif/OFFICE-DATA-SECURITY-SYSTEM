using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

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

    /// <summary>For installer uploads: same pinned connection, no overall time limit (the user can cancel).</summary>
    private readonly HttpClient _transfer;

    private readonly HttpMessageHandler? _handler;

    public ApiClient(Uri serverAddress, X509Certificate2 pinnedCa)
    {
        _handler = ServerTrust.CreatePinnedHandler(pinnedCa);
        _http = new HttpClient(_handler, disposeHandler: false) { BaseAddress = serverAddress, Timeout = TimeSpan.FromSeconds(20) };
        _transfer = new HttpClient(_handler, disposeHandler: false) { BaseAddress = serverAddress, Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>For tests and advanced hosting: uses the given client as-is.</summary>
    public ApiClient(HttpClient http)
    {
        _http = http;
        _transfer = http;
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

    public void Dispose()
    {
        _http.Dispose();
        if (!ReferenceEquals(_transfer, _http))
        {
            _transfer.Dispose();
        }

        _handler?.Dispose();
    }

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

    public Task<EnrollmentCodeResponse> CreateEnrollmentCodeAsync(CancellationToken ct = default) =>
        SendAsync<EnrollmentCodeResponse>(HttpMethod.Post, ApiRoutes.EnrollmentCodes, null, ct);

    public Task<PagedResult<ComputerSummary>> ListComputersAsync(int page, int pageSize, string? search, string? status, CancellationToken ct = default) =>
        SendAsync<PagedResult<ComputerSummary>>(HttpMethod.Get, ApiRoutes.Computers + Query(("page", page), ("pageSize", pageSize), ("search", search), ("status", status)), null, ct);

    public Task<ComputerDetail> GetComputerAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ComputerDetail>(HttpMethod.Get, ApiRoutes.ComputerById(id), null, ct);

    public Task<ComputerSummary> ApproveComputerAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ComputerSummary>(HttpMethod.Post, ApiRoutes.ComputerApprove(id), null, ct);

    public Task<ComputerSummary> RejectComputerAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ComputerSummary>(HttpMethod.Post, ApiRoutes.ComputerReject(id), null, ct);

    public Task<ComputerSummary> RetireComputerAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<ComputerSummary>(HttpMethod.Post, ApiRoutes.ComputerRetire(id), null, ct);

    public Task<ComputerSummary> AssignComputerPolicyAsync(Guid id, Guid? policyId, CancellationToken ct = default) =>
        SendAsync<ComputerSummary>(HttpMethod.Put, ApiRoutes.ComputerPolicy(id), new AssignPolicyRequest(policyId), ct);

    public Task<List<StaffReference>> AssignComputerStaffAsync(Guid id, IReadOnlyList<Guid> staffIds, CancellationToken ct = default) =>
        SendAsync<List<StaffReference>>(HttpMethod.Put, ApiRoutes.ComputerStaff(id), new AssignStaffRequest(staffIds), ct);

    public Task<PagedResult<SecurityEventResponse>> ListEventsAsync(int page, int pageSize, Guid? computerId, string? search, CancellationToken ct = default) =>
        SendAsync<PagedResult<SecurityEventResponse>>(HttpMethod.Get, ApiRoutes.Events + Query(("page", page), ("pageSize", pageSize), ("computerId", computerId), ("search", search)), null, ct);

    public Task<List<ExemptionResponse>> ListExemptionsAsync(Guid computerId, CancellationToken ct = default) =>
        SendAsync<List<ExemptionResponse>>(HttpMethod.Get, ApiRoutes.ComputerExemptions(computerId), null, ct);

    public Task<ExemptionResponse> CreateExemptionAsync(Guid computerId, CreateExemptionRequest request, CancellationToken ct = default) =>
        SendAsync<ExemptionResponse>(HttpMethod.Post, ApiRoutes.ComputerExemptions(computerId), request, ct);

    public Task EndExemptionAsync(Guid computerId, Guid exemptionId, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Delete, ApiRoutes.ComputerExemptionById(computerId, exemptionId), null, ct);

    public Task<List<PolicySummary>> ListPoliciesAsync(CancellationToken ct = default) =>
        SendAsync<List<PolicySummary>>(HttpMethod.Get, ApiRoutes.Policies, null, ct);

    public Task<PolicyDetail> GetPolicyAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<PolicyDetail>(HttpMethod.Get, ApiRoutes.PolicyById(id), null, ct);

    public Task<PolicyDetail> CreatePolicyAsync(SavePolicyRequest request, CancellationToken ct = default) =>
        SendAsync<PolicyDetail>(HttpMethod.Post, ApiRoutes.Policies, request, ct);

    public Task<PolicyDetail> UpdatePolicyAsync(Guid id, SavePolicyRequest request, CancellationToken ct = default) =>
        SendAsync<PolicyDetail>(HttpMethod.Put, ApiRoutes.PolicyById(id), request, ct);

    public Task DeletePolicyAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Delete, ApiRoutes.PolicyById(id), null, ct);

    // ---------------------------------------------------------------- software

    public Task<SoftwareRequestResponse> CreateSoftwareRequestAsync(CreateSoftwareRequest request, CancellationToken ct = default) =>
        SendAsync<SoftwareRequestResponse>(HttpMethod.Post, ApiRoutes.SoftwareRequests, request, ct);

    public Task<List<SoftwareRequestResponse>> ListMySoftwareRequestsAsync(CancellationToken ct = default) =>
        SendAsync<List<SoftwareRequestResponse>>(HttpMethod.Get, ApiRoutes.MySoftwareRequests, null, ct);

    public Task<PagedResult<SoftwareRequestResponse>> ListSoftwareRequestsAsync(int page, int pageSize, string? status, CancellationToken ct = default) =>
        SendAsync<PagedResult<SoftwareRequestResponse>>(HttpMethod.Get, ApiRoutes.SoftwareRequests + Query(("page", page), ("pageSize", pageSize), ("status", status)), null, ct);

    public Task<SoftwareRequestResponse> ApproveSoftwareRequestAsync(Guid id, ApproveSoftwareRequest request, CancellationToken ct = default) =>
        SendAsync<SoftwareRequestResponse>(HttpMethod.Post, ApiRoutes.SoftwareRequestApprove(id), request, ct);

    public Task<SoftwareRequestResponse> RejectSoftwareRequestAsync(Guid id, string? note, CancellationToken ct = default) =>
        SendAsync<SoftwareRequestResponse>(HttpMethod.Post, ApiRoutes.SoftwareRequestReject(id), new RejectSoftwareRequest(note), ct);

    public Task<List<ApprovedSoftwareResponse>> ListApprovedSoftwareAsync(CancellationToken ct = default) =>
        SendAsync<List<ApprovedSoftwareResponse>>(HttpMethod.Get, ApiRoutes.ApprovedSoftware, null, ct);

    public Task<ApprovedSoftwareResponse> CreateApprovedSoftwareAsync(SaveApprovedSoftwareRequest request, CancellationToken ct = default) =>
        SendAsync<ApprovedSoftwareResponse>(HttpMethod.Post, ApiRoutes.ApprovedSoftware, request, ct);

    public Task<ApprovedSoftwareResponse> UpdateApprovedSoftwareAsync(Guid id, SaveApprovedSoftwareRequest request, CancellationToken ct = default) =>
        SendAsync<ApprovedSoftwareResponse>(HttpMethod.Put, ApiRoutes.ApprovedSoftwareById(id), request, ct);

    public Task DeleteApprovedSoftwareAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Delete, ApiRoutes.ApprovedSoftwareById(id), null, ct);

    /// <summary>Uploads an installer file; <paramref name="progress"/> receives the number of bytes sent.</summary>
    public Task<SoftwarePackageResponse> UploadPackageAsync(Guid approvedSoftwareId, UploadPackageOptions options, Stream content, IProgress<long>? progress = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var route = ApiRoutes.ApprovedSoftwarePackages(approvedSoftwareId) + Query(("fileName", options.FileName), ("installerType", options.InstallerType),
            ("silentArguments", options.SilentArguments), ("signerSubject", options.SignerSubject), ("allowUnsigned", options.AllowUnsigned ? "true" : "false"));
        var body = new StreamContent(progress is null ? content : new ProgressStream(content, progress), 81920);
        body.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return SendContentAsync<SoftwarePackageResponse>(_transfer, HttpMethod.Post, route, body, ct);
    }

    public Task DeletePackageAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Delete, ApiRoutes.SoftwarePackageById(id), null, ct);

    public Task<PagedResult<DeploymentResponse>> ListDeploymentsAsync(int page, int pageSize, Guid? computerId, string? status, CancellationToken ct = default) =>
        SendAsync<PagedResult<DeploymentResponse>>(HttpMethod.Get, ApiRoutes.SoftwareDeployments + Query(("page", page), ("pageSize", pageSize), ("computerId", computerId), ("status", status)), null, ct);

    public Task<List<DeploymentResponse>> CreateDeploymentsAsync(CreateDeploymentRequest request, CancellationToken ct = default) =>
        SendAsync<List<DeploymentResponse>>(HttpMethod.Post, ApiRoutes.SoftwareDeployments, request, ct);

    public Task CancelDeploymentAsync(Guid id, CancellationToken ct = default) =>
        SendAsync<object>(HttpMethod.Post, ApiRoutes.DeploymentCancel(id), null, ct);

    public Task<List<SoftwareTitleSummary>> ListSoftwareTitlesAsync(string? search, bool unapprovedOnly, CancellationToken ct = default) =>
        SendAsync<List<SoftwareTitleSummary>>(HttpMethod.Get, ApiRoutes.SoftwareInventory + Query(("search", search), ("unapprovedOnly", unapprovedOnly ? "true" : null)), null, ct);

    public Task<List<InstalledSoftwareResponse>> ListInstalledSoftwareAsync(Guid? computerId, string? name, CancellationToken ct = default) =>
        SendAsync<List<InstalledSoftwareResponse>>(HttpMethod.Get, ApiRoutes.SoftwareInventoryComputers + Query(("computerId", computerId), ("name", name)), null, ct);

    // ---------------------------------------------------------------- plumbing

    private CurrentUserResponse StartSession(SessionResponse session)
    {
        Token = session.Token;
        CurrentUser = session.User;
        return session.User;
    }

    private Task<T> SendAsync<T>(HttpMethod method, string route, object? body, CancellationToken ct) =>
        SendContentAsync<T>(_http, method, route, body is null ? null : JsonContent.Create(body, body.GetType()), ct);

    private async Task<T> SendContentAsync<T>(HttpClient http, HttpMethod method, string route, HttpContent? content, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, new Uri(route, UriKind.Relative)) { Content = content };

        var authenticated = Token is not null;
        if (authenticated)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        }

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct).ConfigureAwait(false);
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

        return response.StatusCode == HttpStatusCode.Forbidden
            ? "Your account is not allowed to do this."
            : string.Create(CultureInfo.InvariantCulture, $"The server reported an error ({(int)response.StatusCode}).");
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

/// <summary>Reports how much of a stream has been read (upload progress).</summary>
internal sealed class ProgressStream(Stream inner, IProgress<long> progress) : Stream
{
    private long _position;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => inner.Length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        Count(await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    private int Count(int read)
    {
        _position += read;
        progress.Report(_position);
        return read;
    }
}
