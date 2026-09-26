using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Core;

/// <summary>
/// Named pipe through which the staff application on the same computer asks the agent for its status
/// (server address, pinned CA) and for sign-in tickets. It offers nothing that changes the agent or policy.
/// Remote (network) access to the pipe is denied.
/// </summary>
public sealed partial class AgentLocalServer(AgentRuntime runtime, ILogger<AgentLocalServer> logger, string pipeName = AgentLocalProtocol.PipeName)
{
    private const int MaxRequestBytes = 1024;
    private const int MaxTicketsPerMinute = 20;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly Queue<DateTimeOffset> _recentTickets = new();

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var first = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe(first);
                first = false;
            }
            catch (IOException ex)
            {
                // Another process already owns the pipe name (possible impersonation attempt); retry later.
                LogPipeUnavailable(logger, ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }

            _ = HandleAsync(pipe, cancellationToken);
        }
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                var line = await ReadLineAsync(pipe, timeout.Token).ConfigureAwait(false);
                var request = line is null ? null : JsonSerializer.Deserialize<AgentLocalRequest>(line, Json);
                var response = await ProcessAsync(request, timeout.Token).ConfigureAwait(false);
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response, Json) + "\n");
                await pipe.WriteAsync(bytes, timeout.Token).ConfigureAwait(false);
                await pipe.FlushAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or JsonException or OperationCanceledException)
            {
                LogRequestFailed(logger, ex.Message);
            }
        }
    }

    internal async Task<AgentLocalResponse> ProcessAsync(AgentLocalRequest? request, CancellationToken cancellationToken)
    {
        switch (request?.Command)
        {
            case AgentLocalProtocol.StatusCommand:
                return new AgentLocalResponse(true, runtime.GetLocalStatus(), null, null);

            case AgentLocalProtocol.LoginTicketCommand:
                if (!AllowTicket())
                {
                    return new AgentLocalResponse(false, null, null, "Too many sign-in attempts. Wait a minute.");
                }

                try
                {
                    return new AgentLocalResponse(true, null, await runtime.GetLoginTicketAsync(cancellationToken).ConfigureAwait(false), null);
                }
                catch (Exception ex) when (ex is AgentServerException or InvalidOperationException)
                {
                    return new AgentLocalResponse(false, null, null, ex.Message);
                }

            default:
                return new AgentLocalResponse(false, null, null, "Unknown request.");
        }
    }

    private bool AllowTicket()
    {
        lock (_recentTickets)
        {
            var now = DateTimeOffset.UtcNow;
            while (_recentTickets.Count > 0 && now - _recentTickets.Peek() > TimeSpan.FromMinutes(1))
            {
                _recentTickets.Dequeue();
            }

            if (_recentTickets.Count >= MaxTicketsPerMinute)
            {
                return false;
            }

            _recentTickets.Enqueue(now);
            return true;
        }
    }

    private NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return OperatingSystem.IsWindows()
            ? CreateWindowsPipe(options)
            : new NamedPipeServerStream(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, options);
    }

    [SupportedOSPlatform("windows")]
    private NamedPipeServerStream CreateWindowsPipe(PipeOptions options)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options, 0, 0, security);
    }

    private static async Task<string?> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxRequestBytes];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0 || buffer[length] == (byte)'\n')
            {
                break;
            }

            length++;
        }

        return length == 0 ? null : Encoding.UTF8.GetString(buffer, 0, length);
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Local status pipe could not be created: {Message}")]
    private static partial void LogPipeUnavailable(ILogger logger, string message);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Local request failed: {Message}")]
    private static partial void LogRequestFailed(ILogger logger, string message);
}
