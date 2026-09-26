using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Client.Core;

/// <summary>
/// Talks to the security agent on this computer. On Windows it first checks that the pipe is served
/// by the installed agent program, so a fake "agent" started by a user cannot point the staff
/// application at a different server.
/// </summary>
public static partial class AgentLocalClient
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Returns the agent's status, or null when no (trusted) agent is running on this computer.</summary>
    public static async Task<AgentLocalStatus?> TryGetStatusAsync(string pipeName = AgentLocalProtocol.PipeName, bool? verifyServer = null, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(AgentLocalProtocol.StatusCommand, pipeName, verifyServer, cancellationToken).ConfigureAwait(false);
        return response is { Success: true } ? response.Status : null;
    }

    /// <summary>Gets a one-time ticket proving a sign-in happens on this computer, or null if unavailable.</summary>
    public static async Task<string?> TryGetLoginTicketAsync(string pipeName = AgentLocalProtocol.PipeName, bool? verifyServer = null, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(AgentLocalProtocol.LoginTicketCommand, pipeName, verifyServer, cancellationToken).ConfigureAwait(false);
        return response is { Success: true } ? response.LoginTicket : null;
    }

    private static async Task<AgentLocalResponse?> SendAsync(string command, string pipeName, bool? verifyServer, CancellationToken cancellationToken)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await pipe.ConnectAsync(TimeSpan.FromSeconds(2), timeout.Token).ConfigureAwait(false);

            if ((verifyServer ?? OperatingSystem.IsWindows()) && (!OperatingSystem.IsWindows() || !IsServedByInstalledAgent(pipe)))
            {
                return null;
            }

            var request = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new AgentLocalRequest(command), Json) + "\n");
            await pipe.WriteAsync(request, timeout.Token).ConfigureAwait(false);
            await pipe.FlushAsync(timeout.Token).ConfigureAwait(false);

            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            var line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            return line is null ? null : JsonSerializer.Deserialize<AgentLocalResponse>(line, Json);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsServedByInstalledAgent(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var processId))
        {
            return false;
        }

        const uint ProcessQueryLimitedInformation = 0x1000;
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process.IsInvalid)
        {
            return false;
        }

        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        if (!QueryFullProcessImageName(process, 0, ref buffer[0], ref size))
        {
            return false;
        }

        var path = new string(buffer, 0, (int)size);
        return string.Equals(Path.GetFullPath(path), Path.GetFullPath(AgentLocalProtocol.InstalledAgentExecutable()), StringComparison.OrdinalIgnoreCase);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, ref char exeName, ref uint size);
}
