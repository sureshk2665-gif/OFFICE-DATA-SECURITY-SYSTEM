using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Agent.Core;

/// <summary>Checks an installer's digital signature (Windows: WinVerifyTrust).</summary>
public interface IInstallerVerifier
{
    SignatureCheck Check(string path);
}

public sealed class AuthenticodeInstallerVerifier : IInstallerVerifier
{
    public SignatureCheck Check(string path) => Authenticode.Check(path);
}

public sealed record InstallerOutcome(string Status, int? ExitCode, string Message);

/// <summary>Runs a verified installer silently.</summary>
public interface IInstallerRunner
{
    Task<InstallerOutcome> RunAsync(AgentJob job, string installerPath, CancellationToken cancellationToken);
}

/// <summary>
/// Runs MSI packages with msiexec (quiet, no automatic restart, verbose log) and EXE installers with the
/// administrator-provided silent options. No shell is involved and nothing but the verified file is run.
/// </summary>
public sealed class ProcessInstallerRunner(TimeSpan? timeout = null) : IInstallerRunner
{
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromMinutes(60);

    public async Task<InstallerOutcome> RunAsync(AgentJob job, string installerPath, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);
        var logPath = installerPath + ".log";
        ProcessStartInfo start;
        if (job.InstallerType == InstallerTypes.Msi)
        {
            start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"))
            {
                Arguments = $"/i \"{installerPath}\" /qn /norestart /l*v \"{logPath}\" {job.SilentArguments}".TrimEnd(),
            };
        }
        else
        {
            start = new ProcessStartInfo(installerPath) { Arguments = job.SilentArguments ?? string.Empty };
        }

        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.WorkingDirectory = Path.GetDirectoryName(installerPath)!;

        using var process = Process.Start(start) ?? throw new InvalidOperationException("The installer could not be started.");
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(_timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(entireProcessTree: true);
            return new InstallerOutcome(JobStatuses.Failed, null, $"The installer did not finish within {_timeout.TotalMinutes:0} minutes and was stopped. It may be waiting for input: check the silent install options.");
        }

        var code = process.ExitCode;
        var status = code switch
        {
            0 => JobStatuses.Succeeded,
            3010 or 1641 => JobStatuses.SucceededRebootRequired,
            _ => JobStatuses.Failed,
        };
        var message = status switch
        {
            JobStatuses.Succeeded => "Installed successfully.",
            JobStatuses.SucceededRebootRequired => "Installed; Windows must restart to finish.",
            _ => code switch
            {
                1602 => "Installation was cancelled.",
                1603 => "The installer reported a fatal error (1603).",
                1618 => "Another installation was in progress (1618). It will not be retried automatically.",
                1638 => "Another version of this program is already installed (1638).",
                _ => string.Create(CultureInfo.InvariantCulture, $"The installer failed with exit code {code}."),
            } + LogTail(logPath),
        };

        TryDelete(logPath);
        return new InstallerOutcome(status, code, message);
    }

    private static string LogTail(string logPath)
    {
        try
        {
            if (!File.Exists(logPath))
            {
                return string.Empty;
            }

            // msiexec writes UTF-16 logs; keep the lines that mention errors.
            var lines = File.ReadAllLines(logPath, Encoding.Unicode)
                .Where(l => l.Contains("error", StringComparison.OrdinalIgnoreCase) || l.Contains("return value 3", StringComparison.OrdinalIgnoreCase))
                .TakeLast(8);
            var text = string.Join(" | ", lines);
            return text.Length == 0 ? string.Empty : " Log: " + (text.Length > 1200 ? text[^1200..] : text);
        }
        catch (IOException)
        {
            return string.Empty;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }
}

/// <summary>
/// Performs approved installations: download, verify SHA-256 and signature, run, report. Anything that
/// fails verification is never run.
/// </summary>
public sealed partial class InstallationProcessor(
    AgentPaths paths,
    IInstallerVerifier verifier,
    IInstallerRunner runner,
    PendingEventStore events,
    ILogger logger)
{
    public async Task ProcessAsync(AgentServerClient client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        var jobs = await client.GetJobsAsync(cancellationToken).ConfigureAwait(false);
        foreach (var job in jobs)
        {
            await ProcessJobAsync(client, job, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessJobAsync(AgentServerClient client, AgentJob job, CancellationToken cancellationToken)
    {
        try
        {
            await client.StartJobAsync(job.JobId, cancellationToken).ConfigureAwait(false);
        }
        catch (AgentServerException ex) when (!ex.IsUnreachable)
        {
            LogJobRefused(logger, job.JobId, ex.Message);
            return; // Cancelled, or given up after too many attempts.
        }

        var directory = Path.Combine(paths.DataDirectory, "installers");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, job.JobId.ToString("N") + "-" + SafeFileName(job.FileName));
        try
        {
            await using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await client.DownloadPackageAsync(job.JobId, file, job.SizeBytes, cancellationToken).ConfigureAwait(false);
            }

            var failure = Verify(job, path);
            InstallerOutcome outcome;
            if (failure is not null)
            {
                events.Enqueue(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical, $"Installer for {job.SoftwareName} was NOT run: {failure}");
                outcome = new InstallerOutcome(JobStatuses.Failed, null, "Not installed: " + failure);
            }
            else
            {
                LogInstalling(logger, job.SoftwareName, job.FileName);
                outcome = await runner.RunAsync(job, path, cancellationToken).ConfigureAwait(false);
            }

            await client.SendJobResultAsync(job.JobId, new AgentJobResult(outcome.Status, outcome.ExitCode, outcome.Message), cancellationToken).ConfigureAwait(false);
            LogJobFinished(logger, job.SoftwareName, outcome.Status);
        }
        catch (InvalidDataException ex)
        {
            await client.SendJobResultAsync(job.JobId, new AgentJobResult(JobStatuses.Failed, null, "Not installed: " + ex.Message), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>Returns why the installer must not run, or null when it passed every check.</summary>
    private string? Verify(AgentJob job, string path)
    {
        var info = new FileInfo(path);
        if (info.Length != job.SizeBytes)
        {
            return "the downloaded file has the wrong size.";
        }

        using (var stream = File.OpenRead(path))
        {
            var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            if (!string.Equals(hash, job.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return "the file's SHA-256 fingerprint does not match the approved installer.";
            }
        }

        var signature = verifier.Check(path);
        switch (signature.State)
        {
            case SignatureState.Valid when job.SignerSubject is not null && !string.Equals(signature.SignerSubject, job.SignerSubject, StringComparison.Ordinal):
                return $"it is signed by '{signature.SignerSubject}', not by the approved publisher '{job.SignerSubject}'.";
            case SignatureState.Valid:
                return null;
            case SignatureState.NotSigned when job.AllowUnsigned:
                return null;
            case SignatureState.NotSigned:
                return "it has no digital signature and unsigned installers were not allowed for it.";
            case SignatureState.Unavailable when job.AllowUnsigned:
                return null;
            default:
                return signature.Detail ?? "its digital signature could not be verified.";
        }
    }

    private static string SafeFileName(string name) =>
        new(Path.GetFileName(name).Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_').Take(100).ToArray());

    [LoggerMessage(Level = LogLevel.Warning, Message = "Installation job {JobId} refused by the server: {Message}")]
    private static partial void LogJobRefused(ILogger logger, Guid jobId, string message);

    [LoggerMessage(Level = LogLevel.Information, Message = "Installing approved software {Software} ({File}).")]
    private static partial void LogInstalling(ILogger logger, string software, string file);

    [LoggerMessage(Level = LogLevel.Information, Message = "Installation of {Software} finished: {Status}.")]
    private static partial void LogJobFinished(ILogger logger, string software, string status);
}
