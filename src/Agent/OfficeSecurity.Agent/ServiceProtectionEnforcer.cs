using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Win32;
using OfficeSecurity.Agent.Core;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;

namespace OfficeSecurity.Agent;

/// <summary>
/// Agent tamper protection: checks that the service starts automatically, restarts after failure and cannot be
/// stopped, reconfigured or deleted by anyone but SYSTEM and Administrators. Anything changed is put back.
/// Local administrators can always stop the agent; that cannot be prevented (see the threat model).
/// </summary>
internal sealed class ServiceProtectionEnforcer(IEnforcementEvents events, TimeProvider clock) : IEnforcer
{
    // Rights that must be reserved to SYSTEM and Administrators.
    private const int Dangerous = 0x0002 /* change config */ | 0x0020 /* stop */ | 0x0040 /* pause */ | 0x10000 /* delete */ | 0x40000 /* write DAC */ | 0x80000 /* write owner */;
    private const int RestartAction = 1; // SC_ACTION_RESTART

    public SecurityControl Control => SecurityControl.AgentTamperProtection;

    public Task<ControlStatus> ApplyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        if (!WindowsServiceHelpers.IsWindowsService())
        {
            return Task.FromResult(Status(ControlState.NotConfigured, "Not running as the installed Windows service."));
        }

        var problems = Check();
        if (problems.Count > 0 && Environment.ProcessPath is { } exe)
        {
            ServiceInstaller.CreateOrUpdate(exe);
            events.Raise(SecurityEventType.PolicyTamperAttempt, EventSeverities.Critical,
                "The agent's service settings had been changed and were restored: " + string.Join("; ", problems));
            problems = Check();
        }

        return Task.FromResult(problems.Count == 0 ? Enforced() : Status(ControlState.Failed, string.Join("; ", problems)));
    }

    public Task<ControlStatus> VerifyAsync(SecurityPolicyDocument policy, CancellationToken cancellationToken)
    {
        if (!WindowsServiceHelpers.IsWindowsService())
        {
            return Task.FromResult(Status(ControlState.NotConfigured, "Not running as the installed Windows service."));
        }

        var problems = Check();
        return Task.FromResult(problems.Count == 0 ? Enforced() : Status(ControlState.Failed, string.Join("; ", problems)));
    }

    /// <summary>Returns what is wrong with the service configuration (empty when everything is as installed).</summary>
    internal static List<string> Check()
    {
        var problems = new List<string>();
        using (var service = new ServiceController(AgentPaths.ServiceName))
        {
            if (service.StartType != ServiceStartMode.Automatic)
            {
                problems.Add($"start type is {service.StartType}, not Automatic");
            }
        }

        using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AgentPaths.ServiceName}"))
        {
            // SERVICE_FAILURE_ACTIONS as stored by the Service Control Manager: reset period, two string offsets,
            // the action count, an offset, then (type, delay) pairs.
            if (!RestartsOnFailure(key?.GetValue("FailureActions") as byte[]))
            {
                problems.Add("automatic restart after failure is not configured");
            }
        }

        var sddl = SdShow();
        var descriptor = new RawSecurityDescriptor(sddl);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        foreach (var ace in descriptor.DiscretionaryAcl?.OfType<CommonAce>() ?? [])
        {
            if (ace.AceType == AceType.AccessAllowed && (ace.AccessMask & Dangerous) != 0 && ace.SecurityIdentifier != system && ace.SecurityIdentifier != admins)
            {
                problems.Add($"{Name(ace.SecurityIdentifier)} may stop or reconfigure the service");
            }
        }

        return problems;
    }

    private static bool RestartsOnFailure(byte[]? actions)
    {
        if (actions is null || actions.Length < 20)
        {
            return false;
        }

        var count = BitConverter.ToInt32(actions, 12);
        if (count < 1 || actions.Length < 20 + (count * 8))
        {
            return false;
        }

        for (var i = 0; i < count; i++)
        {
            if (BitConverter.ToInt32(actions, 20 + (i * 8)) != RestartAction)
            {
                return false;
            }
        }

        return true;
    }

    private static string SdShow()
    {
        var start = new ProcessStartInfo("sc.exe") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("sdshow");
        start.ArgumentList.Add(AgentPaths.ServiceName);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not run sc.exe.");
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).First(l => l.StartsWith("D:", StringComparison.Ordinal) || l.StartsWith("O:", StringComparison.Ordinal));
    }

    private static string Name(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return sid.Value;
        }
    }

    private ControlStatus Enforced() => Status(ControlState.Enforced,
        "Service starts with Windows, restarts automatically if stopped, and only SYSTEM and Administrators can stop or change it. Local administrators can still stop it.");

    private ControlStatus Status(ControlState state, string detail) => new(Control, state, detail, clock.GetUtcNow());
}
