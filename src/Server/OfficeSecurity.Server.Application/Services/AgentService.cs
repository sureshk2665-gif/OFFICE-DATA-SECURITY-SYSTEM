using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;
using OfficeSecurity.Server.Application.Abstractions;
using OfficeSecurity.Server.Application.Common;
using OfficeSecurity.Server.Application.Security;
using OfficeSecurity.Server.Domain;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Proof that a staff sign-in is happening on a specific enrolled computer.</summary>
public sealed record ComputerLoginTicket(Guid ComputerId);

/// <summary>Everything the security agent on a computer talks to the server about.</summary>
public sealed class AgentService(
    IServerDbContext db,
    AuditLog audit,
    IDeviceCertificateAuthority certificateAuthority,
    IPolicySigningService policySigner,
    PolicyService policies,
    SoftwareService software,
    RecoveryKeyService recoveryKeys,
    OneTimeTicketStore<ComputerLoginTicket> loginTickets,
    TimeProvider clock)
{
    public const int MaxEventsPerUpload = 500;
    public const int MaxDevicesPerInventory = 500;
    public static readonly TimeSpan LoginTicketLifetime = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // ---------------------------------------------------------------- enrollment (before approval)

    public async Task<Result<AgentEnrollResponse>> EnrollAsync(AgentEnrollRequest request, RequestContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var now = clock.GetUtcNow();
        var hash = SecretCodes.HashForStorage(SecretCodes.NormalizeSetupCode(request.EnrollmentCode));
        var code = await db.EnrollmentCodes.FirstOrDefaultAsync(c => c.CodeHash == hash, cancellationToken).ConfigureAwait(false);
        if (code is null || code.UsedAtUtc is not null || code.ExpiresAtUtc <= now)
        {
            await audit.RecordAndSaveAsync(context, new AuditRecord("computer.enroll", AuditOutcome.Failure,
                Details: $"{(code is null ? "unknown" : code.UsedAtUtc is not null ? "already used" : "expired")} enrollment code from {Clean(request.Hardware?.ComputerName, 64)}",
                ActorTypeOverride: AuditActorType.Computer), cancellationToken).ConfigureAwait(false);
            return ServiceError.Unauthorized("The enrollment code is not valid or has expired. Create a new code in the dashboard (Computers → Add computer).");
        }

        if (request.Hardware is null || string.IsNullOrWhiteSpace(request.Hardware.ComputerName))
        {
            return ServiceError.Validation("Computer information is missing.");
        }

        if (certificateAuthority.ValidateRequest(request.CertificateRequestPem ?? string.Empty) is { } csrError)
        {
            return ServiceError.Validation(csrError);
        }

        var pollToken = SecretCodes.NewToken();
        var computer = new Computer
        {
            Id = Guid.NewGuid(),
            Hostname = Clean(request.Hardware.ComputerName, 64)!,
            Status = ComputerStatus.PendingApproval,
            EnrollmentCodeId = code.Id,
            CertificateRequestPem = request.CertificateRequestPem,
            PollTokenHash = SecretCodes.HashForStorage(pollToken),
            RegisteredAtUtc = now,
            LastSeenIp = context.SourceIp,
        };
        ApplyHardware(computer, request.Hardware);
        db.Computers.Add(computer);
        code.UsedAtUtc = now;

        await audit.RecordAndSaveAsync(context, new AuditRecord("computer.enroll", TargetType: "Computer", TargetId: computer.Id.ToString(),
            Details: $"{computer.Hostname} is waiting for approval", ActorTypeOverride: AuditActorType.Computer, ActorIdOverride: computer.Id,
            ActorNameOverride: computer.Hostname), cancellationToken).ConfigureAwait(false);
        return new AgentEnrollResponse(computer.Id, pollToken);
    }

    public async Task<Result<AgentEnrollStatusResponse>> GetEnrollmentStatusAsync(AgentEnrollStatusRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var hash = SecretCodes.HashForStorage(request.PollToken ?? string.Empty);
        var computer = await db.Computers.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == request.ComputerId && c.PollTokenHash == hash, cancellationToken).ConfigureAwait(false);
        if (computer is null)
        {
            // Unknown, or rejected/retired (the poll token is cleared when an administrator decides).
            return new AgentEnrollStatusResponse(EnrollmentStatuses.Rejected, null, null);
        }

        return computer.Status == ComputerStatus.Trusted
            ? new AgentEnrollStatusResponse(EnrollmentStatuses.Approved, computer.CertificatePem, policySigner.PublicKeyBase64)
            : new AgentEnrollStatusResponse(EnrollmentStatuses.PendingApproval, null, null);
    }

    // ---------------------------------------------------------------- enrolled agent (mutual TLS)

    /// <summary>Resolves a client certificate thumbprint to a trusted computer id, or null.</summary>
    public async Task<(Guid Id, string Hostname)?> FindTrustedComputerAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        var computer = await db.Computers.AsNoTracking()
            .Where(c => c.CertificateThumbprint == thumbprint && c.Status == ComputerStatus.Trusted)
            .Select(c => new { c.Id, c.Hostname })
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
        return computer is null ? null : (computer.Id, computer.Hostname);
    }

    public async Task<AgentHeartbeatResponse> HeartbeatAsync(Guid computerId, AgentHeartbeatRequest request, string? sourceIp, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var computer = await db.Computers.FirstAsync(c => c.Id == computerId, cancellationToken).ConfigureAwait(false);
        var controls = (request.Controls ?? []).Take(100).ToList();

        computer.LastSeenAtUtc = clock.GetUtcNow();
        computer.LastSeenIp = sourceIp;
        computer.AgentVersion = Clean(request.AgentVersion, 64);
        computer.AppliedPolicyVersion = request.AppliedPolicyVersion;
        computer.ControlStatusJson = JsonSerializer.Serialize(controls, Json);
        computer.FailedControls = controls.Count(c => c.State == ControlState.Failed);

        var settings = await policies.GetEffectiveSettingsAsync(computer, cancellationToken).ConfigureAwait(false);
        computer.HeartbeatIntervalSeconds = settings.Agent.HeartbeatIntervalSeconds;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return new AgentHeartbeatResponse(computer.PolicyVersion, computer.HeartbeatIntervalSeconds,
            await software.CountPendingJobsAsync(computerId, cancellationToken).ConfigureAwait(false));
    }

    public async Task<SignedPolicyEnvelope> GetPolicyAsync(Guid computerId, CancellationToken cancellationToken = default)
    {
        var computer = await db.Computers.AsNoTracking().FirstAsync(c => c.Id == computerId, cancellationToken).ConfigureAwait(false);
        return await policies.GetSignedPolicyAsync(computer, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Result<Done>> ReportInventoryAsync(Guid computerId, AgentInventoryRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Hardware is null || (request.Devices?.Count ?? 0) > MaxDevicesPerInventory)
        {
            return ServiceError.Validation("Inventory is missing or too large.");
        }

        var computer = await db.Computers.FirstAsync(c => c.Id == computerId, cancellationToken).ConfigureAwait(false);
        ApplyHardware(computer, request.Hardware);
        if (Clean(request.Hardware.ComputerName, 64) is { Length: > 0 } hostname)
        {
            computer.Hostname = hostname;
        }

        var now = clock.GetUtcNow();
        var reported = (request.Devices ?? [])
            .Where(d => !string.IsNullOrWhiteSpace(d.InstanceId))
            .GroupBy(d => d.InstanceId.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        var known = await db.Devices.Where(d => d.ComputerId == computerId).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var device in known)
        {
            device.IsConnected = false;
        }

        foreach (var device in reported)
        {
            var instanceId = Clean(device.InstanceId, 400)!;
            var existing = known.FirstOrDefault(k => string.Equals(k.InstanceId, instanceId, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                existing = new DeviceInventoryItem
                {
                    ComputerId = computerId,
                    InstanceId = instanceId,
                    Name = Clean(device.Name, 256) ?? "(unnamed device)",
                    DeviceClass = Clean(device.DeviceClass, 64) ?? "Unknown",
                    FirstSeenUtc = now,
                };
                db.Devices.Add(existing);
            }

            existing.Name = Clean(device.Name, 256) ?? existing.Name;
            existing.DeviceClass = Clean(device.DeviceClass, 64) ?? existing.DeviceClass;
            existing.Manufacturer = Clean(device.Manufacturer, 256);
            existing.ParentInstanceId = Clean(device.ParentInstanceId, 400) ?? existing.ParentInstanceId;
            existing.IsConnected = true;
            existing.LastSeenUtc = now;
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (request.Software is { } installed)
        {
            await software.ApplyInventoryAsync(computerId, installed, cancellationToken).ConfigureAwait(false);
        }

        if (request.RecoveryKeys is { Count: > 0 } keys)
        {
            await recoveryKeys.StoreAsync(computerId, keys, cancellationToken).ConfigureAwait(false);
        }

        return Done.Value;
    }

    public async Task<Result<AgentEventsResponse>> ReportEventsAsync(Guid computerId, AgentEventsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var events = request.Events ?? [];
        if (events.Count > MaxEventsPerUpload)
        {
            return ServiceError.Validation($"At most {MaxEventsPerUpload} events can be uploaded at once.");
        }

        var ids = events.Select(e => e.EventId).Distinct().ToList();
        var already = await db.SecurityEvents.Where(e => e.ComputerId == computerId && ids.Contains(e.EventId))
            .Select(e => e.EventId).ToListAsync(cancellationToken).ConfigureAwait(false);
        var now = clock.GetUtcNow();
        var accepted = 0;
        foreach (var item in events.Where(e => e.EventId != Guid.Empty && !already.Contains(e.EventId)).DistinctBy(e => e.EventId))
        {
            db.SecurityEvents.Add(new SecurityEvent
            {
                ComputerId = computerId,
                EventId = item.EventId,
                EventType = Enum.IsDefined(item.Type) ? item.Type.ToString() : "Unknown",
                Severity = item.Severity is EventSeverities.Information or EventSeverities.Warning or EventSeverities.Critical ? item.Severity : EventSeverities.Information,
                // A wrong clock on the computer must not place events in the future.
                OccurredAtUtc = item.OccurredAtUtc > now ? now : item.OccurredAtUtc,
                ReceivedAtUtc = now,
                Details = Clean(item.Details, 2000),
            });
            accepted++;
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return new AgentEventsResponse(accepted);
    }

    public ComputerLoginTicketResponse IssueLoginTicket(Guid computerId) =>
        new(loginTickets.Issue(new ComputerLoginTicket(computerId), LoginTicketLifetime), clock.GetUtcNow() + LoginTicketLifetime);

    private static void ApplyHardware(Computer computer, HardwareInventory hardware)
    {
        computer.HardwareJson = JsonSerializer.Serialize(hardware with
        {
            ComputerName = Clean(hardware.ComputerName, 64) ?? computer.Hostname,
            OsName = Clean(hardware.OsName, 128),
            OsVersion = Clean(hardware.OsVersion, 64),
            OsBuild = Clean(hardware.OsBuild, 64),
            OsEdition = Clean(hardware.OsEdition, 64),
            Manufacturer = Clean(hardware.Manufacturer, 128),
            Model = Clean(hardware.Model, 128),
            SerialNumber = Clean(hardware.SerialNumber, 128),
            Processor = Clean(hardware.Processor, 128),
            DomainOrWorkgroup = Clean(hardware.DomainOrWorkgroup, 128),
        }, Json);
        computer.OsName = Clean(hardware.OsName, 128);
        computer.OsEdition = Clean(hardware.OsEdition, 64);
    }

    private static string? Clean(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = new string(value.Trim().Where(c => !char.IsControl(c)).ToArray());
        return text.Length <= maxLength ? text : text[..maxLength];
    }
}
