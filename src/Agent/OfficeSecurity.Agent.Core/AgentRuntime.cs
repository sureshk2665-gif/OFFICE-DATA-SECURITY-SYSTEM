using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent.Core;

public sealed class AgentRuntimeOptions
{
    public string AgentVersion { get; init; } = "0.0.0";

    /// <summary>How often connected devices are checked (for connection/disconnection events).</summary>
    public TimeSpan DevicePollInterval { get; init; } = TimeSpan.FromSeconds(15);

    public TimeSpan InventoryInterval { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>While waiting for approval: poll quickly at first so a prompt approval takes effect quickly.</summary>
    public TimeSpan ApprovalPollFast { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan ApprovalPollSlow { get; init; } = TimeSpan.FromSeconds(60);

    public TimeSpan ApprovalFastPeriod { get; init; } = TimeSpan.FromMinutes(10);

    public int EventUploadBatchSize { get; init; } = 200;
}

/// <summary>
/// The agent's behaviour, independent of how it is hosted (Windows Service, console, tests). The host
/// calls <see cref="RunOnceAsync"/> repeatedly and waits for the returned delay in between.
/// </summary>
public sealed partial class AgentRuntime : IDisposable
{
    private readonly AgentConfigStore _configStore;
    private readonly IDeviceKeyStore _keys;
    private readonly IInventoryCollector _inventory;
    private readonly EnforcementCoordinator _enforcement;
    private readonly PendingEventStore _events;
    private readonly PolicyCache _policyCache;
    private readonly TimeProvider _clock;
    private readonly ILogger _logger;
    private readonly AgentRuntimeOptions _options;
    private readonly Func<AgentConfig, AgentServerClient>? _clientFactory;
    private readonly Lock _clientGate = new();

    private AgentServerClient? _client;
    private string? _clientKey;
    private bool _started;
    private Dictionary<string, ConnectedDevice>? _lastDevices;
    private DateTimeOffset _nextHeartbeat;
    private DateTimeOffset _nextInventory;
    private DateTimeOffset _pendingSince;
    private long _rejectedPolicyVersion;
    private int _consecutiveFailures;

    public AgentRuntime(
        AgentConfigStore configStore,
        IDeviceKeyStore keys,
        IInventoryCollector inventory,
        EnforcementCoordinator enforcement,
        PendingEventStore events,
        PolicyCache policyCache,
        TimeProvider clock,
        ILogger<AgentRuntime> logger,
        AgentRuntimeOptions options,
        Func<AgentConfig, AgentServerClient>? clientFactory = null)
    {
        _configStore = configStore;
        _keys = keys;
        _inventory = inventory;
        _enforcement = enforcement;
        _events = events;
        _policyCache = policyCache;
        _clock = clock;
        _logger = logger;
        _options = options;
        _clientFactory = clientFactory;
    }

    /// <summary>The policy currently enforced (version 0 = nothing received yet; every control off).</summary>
    public SecurityPolicyDocument CurrentPolicy { get; private set; } = UnconfiguredPolicy();

    public IReadOnlyList<ControlStatus> Controls { get; private set; } = [];

    public void Dispose()
    {
        lock (_clientGate)
        {
            _client?.Dispose();
            _client = null;
        }
    }

    /// <summary>Performs one step of work and returns how long to wait before the next step.</summary>
    public async Task<TimeSpan> RunOnceAsync(CancellationToken cancellationToken)
    {
        if (!_started)
        {
            await StartAsync(cancellationToken).ConfigureAwait(false);
        }

        var config = _configStore.Load();
        try
        {
            var delay = config.State switch
            {
                AgentState.Enrolling => await EnrollAsync(config, cancellationToken).ConfigureAwait(false),
                AgentState.PendingApproval => await PollApprovalAsync(config, cancellationToken).ConfigureAwait(false),
                AgentState.Enrolled => await RunEnrolledAsync(config, cancellationToken).ConfigureAwait(false),
                _ => TimeSpan.FromMinutes(5),
            };
            _consecutiveFailures = 0;
            return delay;
        }
        catch (AgentServerException ex) when (ex.IsUnreachable)
        {
            // Offline: keep enforcing the cached policy and queueing events; retry with back-off.
            _consecutiveFailures++;
            LogServerUnreachable(_logger, ex.Message);
            return TimeSpan.FromSeconds(Math.Min(300, 15 * Math.Pow(2, Math.Min(_consecutiveFailures - 1, 5))));
        }
        catch (AgentServerException ex) when (config.State == AgentState.Enrolled && ex.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            // The server no longer accepts this computer (removed from management). Keep the last policy.
            _configStore.Save(config with { State = AgentState.Retired, LastError = "The server no longer accepts this computer. It may have been removed from management in the dashboard." });
            LogRetired(_logger);
            return TimeSpan.FromHours(1);
        }
        catch (AgentServerException ex)
        {
            // Other server errors (e.g. temporary overload): try again later.
            LogServerError(_logger, ex.Message);
            return TimeSpan.FromMinutes(1);
        }
    }

    /// <summary>What the staff application on this computer may know about the agent.</summary>
    public AgentLocalStatus GetLocalStatus()
    {
        var config = _configStore.Load();
        return new AgentLocalStatus(config.State.ToString(), config.ComputerId,
            config.State == AgentState.Enrolled ? config.ServerAddress : null,
            config.State == AgentState.Enrolled ? config.CaCertificateBase64 : null,
            config.LastError ?? Describe(config.State));
    }

    /// <summary>Asks the server for a one-time ticket proving a staff sign-in happens on this computer.</summary>
    public async Task<string> GetLoginTicketAsync(CancellationToken cancellationToken)
    {
        var config = _configStore.Load();
        if (config.State != AgentState.Enrolled)
        {
            throw new InvalidOperationException("This computer is not approved yet.");
        }

        var ticket = await GetClient(config).GetLoginTicketAsync(cancellationToken).ConfigureAwait(false);
        return ticket.Ticket;
    }

    // ---------------------------------------------------------------- start-up

    private async Task StartAsync(CancellationToken cancellationToken)
    {
        _started = true;
        var config = _configStore.Load();
        if (config is { State: AgentState.Enrolled or AgentState.Retired, ComputerId: { } computerId, PolicySigningPublicKey: { } key })
        {
            var result = _policyCache.Load(new PolicyVerifier(Convert.FromBase64String(key)), computerId);
            if (result is { IsValid: true })
            {
                CurrentPolicy = result.Document!;
            }
            else if (result is not null)
            {
                // The cached file was changed or damaged: do not trust it. The server sends a fresh copy.
                _events.Enqueue(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                    $"The locally stored policy was rejected ({result.Reason}): {result.Detail}");
                _policyCache.Delete();
                LogCachedPolicyRejected(_logger, result.Reason.ToString());
            }
        }

        Controls = await _enforcement.ApplyAsync(CurrentPolicy, cancellationToken).ConfigureAwait(false);
        _events.Enqueue(SecurityEventType.AgentStarted, EventSeverities.Information,
            string.Create(CultureInfo.InvariantCulture, $"Agent {_options.AgentVersion} started; enforcing policy version {CurrentPolicy.Version}."));
        _nextHeartbeat = _nextInventory = _clock.GetUtcNow();
        _pendingSince = _clock.GetUtcNow();
    }

    // ---------------------------------------------------------------- enrollment

    private async Task<TimeSpan> EnrollAsync(AgentConfig config, CancellationToken cancellationToken)
    {
        if (config.KeyName is null)
        {
            // Save the key name before creating the key so a restart never leaves an orphaned key.
            config = config with { KeyName = "OfficeSecurityAgent-" + Guid.NewGuid().ToString("N") };
            _configStore.Save(config);
        }

        string csr;
        using (var key = _keys.GetOrCreate(config.KeyName))
        {
            var request = new CertificateRequest($"CN={SafeName(Environment.MachineName)}", key, HashAlgorithmName.SHA256);
            csr = request.CreateSigningRequestPem();
        }

        try
        {
            var response = await GetClient(config).EnrollAsync(new AgentEnrollRequest(config.EnrollmentCode ?? string.Empty, csr, _inventory.CollectHardware()), cancellationToken).ConfigureAwait(false);
            _configStore.Save(config with
            {
                State = AgentState.PendingApproval,
                ComputerId = response.ComputerId,
                PollToken = response.PollToken,
                EnrollmentCode = null,
                LastError = null,
                LastContactUtc = _clock.GetUtcNow(),
            });
            _pendingSince = _clock.GetUtcNow();
            LogEnrolled(_logger, response.ComputerId);
            return TimeSpan.FromSeconds(2);
        }
        catch (AgentServerException ex) when (ex.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
        {
            _configStore.Save(config with { State = AgentState.EnrollmentFailed, EnrollmentCode = null, LastError = "Registration refused: " + ex.Message });
            LogEnrollmentFailed(_logger, ex.Message);
            return TimeSpan.FromMinutes(5);
        }
    }

    private async Task<TimeSpan> PollApprovalAsync(AgentConfig config, CancellationToken cancellationToken)
    {
        var status = await GetClient(config).GetEnrollmentStatusAsync(
            new AgentEnrollStatusRequest(config.ComputerId!.Value, config.PollToken ?? string.Empty), cancellationToken).ConfigureAwait(false);

        switch (status.Status)
        {
            case EnrollmentStatuses.Approved when status.CertificatePem is not null && status.PolicySigningPublicKey is not null:
                EnsureCertificateMatchesKey(config.KeyName!, status.CertificatePem);
                _configStore.Save(config with
                {
                    State = AgentState.Enrolled,
                    CertificatePem = status.CertificatePem,
                    PolicySigningPublicKey = status.PolicySigningPublicKey,
                    PollToken = null,
                    LastError = null,
                    LastContactUtc = _clock.GetUtcNow(),
                });
                _nextHeartbeat = _nextInventory = _clock.GetUtcNow();
                LogApproved(_logger);
                return TimeSpan.Zero;

            case EnrollmentStatuses.Rejected:
                _configStore.Save(config with { State = AgentState.Rejected, PollToken = null, LastError = "An administrator rejected this computer." });
                return TimeSpan.FromHours(1);

            default:
                return _clock.GetUtcNow() - _pendingSince < _options.ApprovalFastPeriod ? _options.ApprovalPollFast : _options.ApprovalPollSlow;
        }
    }

    private void EnsureCertificateMatchesKey(string keyName, string certificatePem)
    {
        using var certificate = X509Certificate2.CreateFromPem(certificatePem);
        using var certificateKey = certificate.GetECDsaPublicKey() ?? throw new CryptographicException("Issued certificate has no ECDSA key.");
        using var ourKey = _keys.GetOrCreate(keyName);
        if (!certificateKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(ourKey.ExportSubjectPublicKeyInfo()))
        {
            throw new CryptographicException("The certificate issued by the server does not match this computer's key.");
        }
    }

    // ---------------------------------------------------------------- approved: report, receive policy, upload events

    private async Task<TimeSpan> RunEnrolledAsync(AgentConfig config, CancellationToken cancellationToken)
    {
        var client = GetClient(config);
        var now = _clock.GetUtcNow();

        var devices = PollDevices();

        if (now >= _nextHeartbeat)
        {
            var response = await client.HeartbeatAsync(
                new AgentHeartbeatRequest(_options.AgentVersion, CurrentPolicy.Version, Controls, _events.PendingCount()), cancellationToken).ConfigureAwait(false);
            if (response.LatestPolicyVersion > CurrentPolicy.Version && response.LatestPolicyVersion != _rejectedPolicyVersion)
            {
                await UpdatePolicyAsync(client, config, response.LatestPolicyVersion, cancellationToken).ConfigureAwait(false);
            }

            _nextHeartbeat = now + TimeSpan.FromSeconds(Math.Clamp(response.HeartbeatIntervalSeconds, PolicyDocumentValidator.MinHeartbeatSeconds, PolicyDocumentValidator.MaxHeartbeatSeconds));
            _configStore.Save(_configStore.Load() with { LastContactUtc = now, LastError = null });
        }

        if (now >= _nextInventory)
        {
            await client.SendInventoryAsync(new AgentInventoryRequest(_inventory.CollectHardware(), devices), cancellationToken).ConfigureAwait(false);
            _nextInventory = now + _options.InventoryInterval;
        }

        var pending = _events.PeekPending(_options.EventUploadBatchSize);
        if (pending.Count > 0)
        {
            await client.SendEventsAsync(new AgentEventsRequest(pending), cancellationToken).ConfigureAwait(false);
            _events.MarkUploaded(pending.Select(e => e.EventId));
        }

        var untilHeartbeat = _nextHeartbeat - _clock.GetUtcNow();
        return untilHeartbeat < _options.DevicePollInterval ? (untilHeartbeat > TimeSpan.Zero ? untilHeartbeat : TimeSpan.FromSeconds(1)) : _options.DevicePollInterval;
    }

    private async Task UpdatePolicyAsync(AgentServerClient client, AgentConfig config, long announcedVersion, CancellationToken cancellationToken)
    {
        var envelope = await client.GetPolicyAsync(cancellationToken).ConfigureAwait(false);
        var verifier = new PolicyVerifier(Convert.FromBase64String(config.PolicySigningPublicKey!));
        var result = verifier.Verify(envelope, config.ComputerId!.Value, CurrentPolicy.Version);
        if (!result.IsValid)
        {
            _rejectedPolicyVersion = announcedVersion;
            _events.Enqueue(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                $"A policy received from the server was rejected ({result.Reason}): {result.Detail} The previous policy stays in force.");
            LogPolicyRejected(_logger, result.Reason.ToString());
            return;
        }

        _policyCache.Save(envelope);
        CurrentPolicy = result.Document!;
        Controls = await _enforcement.ApplyAsync(CurrentPolicy, cancellationToken).ConfigureAwait(false);
        _events.Enqueue(SecurityEventType.PolicyApplied, EventSeverities.Information,
            string.Create(CultureInfo.InvariantCulture, $"Policy version {CurrentPolicy.Version} applied."));
        LogPolicyApplied(_logger, CurrentPolicy.Version);
    }

    private List<ConnectedDevice> PollDevices()
    {
        var devices = _inventory.CollectDevices().ToList();
        var current = devices.GroupBy(d => d.InstanceId, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        // The first check after start-up records what is already present; later checks log changes.
        if (_lastDevices is not null)
        {
            foreach (var (id, device) in current.Where(c => !_lastDevices.ContainsKey(c.Key)))
            {
                _events.Enqueue(SecurityEventType.DeviceConnected, EventSeverities.Information, $"{device.DeviceClass} connected: {device.Name} [{id}]");
            }

            foreach (var (id, device) in _lastDevices.Where(l => !current.ContainsKey(l.Key)))
            {
                _events.Enqueue(SecurityEventType.DeviceDisconnected, EventSeverities.Information, $"{device.DeviceClass} disconnected: {device.Name} [{id}]");
            }

            if (current.Count != _lastDevices.Count || current.Keys.Any(k => !_lastDevices.ContainsKey(k)))
            {
                _nextInventory = _clock.GetUtcNow();
            }
        }

        _lastDevices = current;
        return devices;
    }

    // ---------------------------------------------------------------- helpers

    private AgentServerClient GetClient(AgentConfig config)
    {
        lock (_clientGate)
        {
            // Rebuild the client when the server, CA or certificate changes (e.g. just approved).
            var key = $"{config.ServerAddress}|{config.CaCertificateBase64?.Length}|{config.State == AgentState.Enrolled}|{config.CertificatePem?.GetHashCode(StringComparison.Ordinal)}";
            if (_client is not null && _clientKey == key)
            {
                return _client;
            }

            _client?.Dispose();
            _client = _clientFactory?.Invoke(config) ?? CreateClient(config);
            _clientKey = key;
            return _client;
        }
    }

    private AgentServerClient CreateClient(AgentConfig config)
    {
        if (!Uri.TryCreate(config.ServerAddress, UriKind.Absolute, out var address) || config.CaCertificateBase64 is null)
        {
            throw new InvalidOperationException("The agent configuration has no server address. Install the agent again.");
        }

        var ca = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(config.CaCertificateBase64));
        var clientCertificate = config.State == AgentState.Enrolled && config.CertificatePem is not null && config.KeyName is not null
            ? _keys.CreateClientCertificate(config.KeyName, config.CertificatePem)
            : null;
        return AgentServerClient.Create(address, ca, clientCertificate);
    }

    private static SecurityPolicyDocument UnconfiguredPolicy() => new()
    {
        Version = 0,
        ComputerId = Guid.Empty,
        IssuedAtUtc = DateTimeOffset.UnixEpoch,
    };

    private static string SafeName(string name) => new(name.Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_').Take(64).ToArray());

    private static string Describe(AgentState state) => state switch
    {
        AgentState.NotConfigured => "The agent is not configured. Install it with an enrollment code.",
        AgentState.Enrolling => "Registering with the server.",
        AgentState.PendingApproval => "Waiting for an administrator to approve this computer.",
        AgentState.Enrolled => "Approved and reporting to the server.",
        AgentState.EnrollmentFailed => "Registration failed. Install the agent again with a new enrollment code.",
        AgentState.Rejected => "An administrator rejected this computer.",
        AgentState.Retired => "This computer was removed from management.",
        _ => state.ToString(),
    };

    [LoggerMessage(Level = LogLevel.Warning, Message = "Server unreachable; continuing offline with the cached policy: {Message}")]
    private static partial void LogServerUnreachable(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Server error; will retry: {Message}")]
    private static partial void LogServerError(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The server no longer accepts this computer's certificate; keeping the last policy.")]
    private static partial void LogRetired(ILogger logger);

    [LoggerMessage(Level = LogLevel.Error, Message = "Cached policy rejected ({Reason}); it was deleted and will be downloaded again.")]
    private static partial void LogCachedPolicyRejected(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Registered with the server as computer {ComputerId}; waiting for approval.")]
    private static partial void LogEnrolled(ILogger logger, Guid computerId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Registration refused by the server: {Message}")]
    private static partial void LogEnrollmentFailed(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Information, Message = "Computer approved by an administrator.")]
    private static partial void LogApproved(ILogger logger);

    [LoggerMessage(Level = LogLevel.Error, Message = "Policy from server rejected ({Reason}); keeping the previous policy.")]
    private static partial void LogPolicyRejected(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Policy version {Version} applied.")]
    private static partial void LogPolicyApplied(ILogger logger, long version);
}
