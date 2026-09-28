using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using OfficeSecurity.Agent.Enforcement;
using OfficeSecurity.Client.Core;
using OfficeSecurity.Contracts;
using OfficeSecurity.Policy;
using Xunit.Abstractions;

namespace OfficeSecurity.Server.IntegrationTests;

/// <summary>
/// Runs only on Windows, as administrator, when OCSS_AGENT_EXE points to the published agent program
/// (the CI pipeline does this on a disposable build machine). Never run it on a production computer: it
/// installs and removes the Office Security Agent service.
/// </summary>
public sealed class WindowsServiceFactAttribute : FactAttribute
{
    public const string AgentExeVariable = "OCSS_AGENT_EXE";

    /// <summary>A small unsigned test MSI (built by the CI pipeline) that the service installs for real.</summary>
    public const string TestMsiVariable = "OCSS_TEST_MSI";

    public WindowsServiceFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows only.";
        }
        else if (Environment.GetEnvironmentVariable(AgentExeVariable) is not { Length: > 0 } path || !File.Exists(path))
        {
            Skip = $"Set {AgentExeVariable} to the published OfficeSecurity.Agent.exe to run this test (disposable Windows machine only).";
        }
    }
}

[Trait("Category", "WindowsService")]
public sealed partial class WindowsAgentServiceTests(ITestOutputHelper output)
{
    [WindowsServiceFact]
    public async Task Installed_service_enrolls_reports_recovers_from_termination_and_uninstalls()
    {
        var exe = Environment.GetEnvironmentVariable(WindowsServiceFactAttribute.AgentExeVariable)!;
        await using var server = new ServerFactory { HttpsPort = FreePort() };
        server.StartRealHttps();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);

        // Faster heartbeats so the test completes quickly.
        var defaultPolicy = Assert.Single((await admin.GetFromJsonAsync<List<PolicySummary>>(ApiRoutes.Policies))!, p => p.IsDefault);
        await SavePolicyAsync(admin, defaultPolicy.Id, s => s with { Agent = new AgentSettings { HeartbeatIntervalSeconds = 15 } });

        var install = await RunAsync(exe, "install", "--server", $"https://localhost:{server.HttpsPort}",
            "--pairing-code", server.PairingCodeFromConnectionInfo(), "--enrollment-code", await server.CreateEnrollmentCodeAsync(owner));
        Assert.True(install == 0, "install failed");

        try
        {
            // 1. The computer appears as waiting for approval.
            var pending = await WaitForAsync(async () =>
                (await admin.GetFromJsonAsync<PagedResult<ComputerSummary>>(ApiRoutes.Computers))!.Items.FirstOrDefault(c => c.Status == ComputerStatuses.PendingApproval),
                TimeSpan.FromSeconds(90), "computer registered");
            Assert.Equal(Environment.MachineName, pending.Hostname, ignoreCase: true);

            // 2. After approval it comes online, reports Windows inventory and applies policy version 1.
            (await admin.PostAsync(new Uri(ApiRoutes.ComputerApprove(pending.Id), UriKind.Relative), null)).EnsureSuccessStatusCode();
            var online = await WaitForAsync(async () =>
            {
                var d = await admin.GetFromJsonAsync<ComputerDetail>(ApiRoutes.ComputerById(pending.Id));
                return d!.Summary.IsOnline && d.Summary.AppliedPolicyVersion == d.Summary.LatestPolicyVersion && d.Hardware?.OsName is not null ? d : null;
            }, TimeSpan.FromSeconds(120), "computer online with policy applied");
            Assert.Contains("Windows", online.Hardware!.OsName, StringComparison.OrdinalIgnoreCase);
            // With the default policy (everything off) only the agent's own protection is active.
            Assert.Equal(ControlState.Enforced, online.Controls.Single(c => c.Control == SecurityControl.AgentTamperProtection).State);
            Assert.All(online.Controls.Where(c => c.Control != SecurityControl.AgentTamperProtection),
                c => Assert.Contains(c.State, new[] { ControlState.NotConfigured, ControlState.NotImplemented }));
            output.WriteLine($"Online: {online.Hardware.OsName} {online.Hardware.OsBuild}, key storage in service, policy v{online.Summary.AppliedPolicyVersion}");

            // 3. A policy change reaches the service.
            await SavePolicyAsync(admin, defaultPolicy.Id, s => s with { Bluetooth = new BluetoothSettings { Mode = BluetoothMode.BlockFileTransfer } });
            await WaitForAsync(async () =>
            {
                var d = await admin.GetFromJsonAsync<ComputerDetail>(ApiRoutes.ComputerById(pending.Id));
                return d!.Summary.AppliedPolicyVersion == online.Summary.LatestPolicyVersion + 1 ? d : null;
            }, TimeSpan.FromSeconds(90), "updated policy applied");

            // 4. Service configuration: automatic start and automatic restart after failure.
            Assert.Contains("AUTO_START", await ScAsync("qc", "OfficeSecurityAgent"), StringComparison.Ordinal);
            Assert.Contains("RESTART", await ScAsync("qfailure", "OfficeSecurityAgent"), StringComparison.Ordinal);

            // 5. Killing the service process: Windows restarts it.
            var pid = await ServicePidAsync();
            Process.GetProcessById(pid).Kill();
            var newPid = await WaitForAsync(async () => await ServicePidAsync() is var p && p != 0 && p != pid ? (int?)p : null,
                TimeSpan.FromSeconds(90), "service restarted after termination");
            output.WriteLine($"Service restarted: PID {pid} -> {newPid}");

            // 6. The staff application's channel: status and a sign-in ticket from the genuine installed agent.
            var status = await WaitForAsync(() => AgentLocalClient.TryGetStatusAsync(verifyServer: true), TimeSpan.FromSeconds(60), "local agent status");
            Assert.Equal("Enrolled", status.State);
            Assert.Equal(pending.Id, status.ComputerId);

            var (staffId, _) = await server.CreateActiveStaffAsync(owner, "EMP-E2E", "Staff member pass 2026");
            (await admin.PutAsJsonAsync(ApiRoutes.ComputerStaff(pending.Id), new AssignStaffRequest([staffId]))).EnsureSuccessStatusCode();
            var ticket = await AgentLocalClient.TryGetLoginTicketAsync(verifyServer: true);
            Assert.NotNull(ticket);
            using var anonymous = server.Client();
            Assert.Equal(HttpStatusCode.OK, (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP-E2E", "Staff member pass 2026", ticket))).StatusCode);

            // 7. Events from both service runs arrived.
            var events = await WaitForAsync(async () =>
            {
                var e = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?computerId={pending.Id}&pageSize=200");
                return e!.Items.Count(x => x.EventType == nameof(SecurityEventType.AgentStarted)) >= 2 ? e : null;
            }, TimeSpan.FromSeconds(90), "start-up events from both runs");
            Assert.Contains(events.Items, e => e.EventType == nameof(SecurityEventType.PolicyApplied));

            // 8. Security controls: applied, verified by Windows itself, restored after tampering, lifted temporarily.
            await EnforcementAsync(admin, defaultPolicy.Id, pending.Id);

            // 9. Approved software installation with the real Windows installer (msiexec) and signature check,
            //    while staff installations are blocked.
            await InstallTestMsiAsync(admin, pending.Id);

            // 10. Part 2: Windows sign-in records, file access records, ransomware protection, BitLocker check and
            //     Application Control (audit, then enforce, then off).
            await Part2Async(admin, defaultPolicy.Id, pending.Id);
        }
        finally
        {
            await RunAsync("net.exe", "user", TestUser, "/delete");
            var uninstall = await RunAsync(exe, "uninstall");
            Assert.Equal(0, uninstall);
            RestoreFirewall();
            if (Environment.GetEnvironmentVariable(WindowsServiceFactAttribute.TestMsiVariable) is { Length: > 0 } msi && File.Exists(msi))
            {
                await RunAsync(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), "/x", msi, "/qn", "/norestart");
            }
        }

        Assert.Contains("1060", await ScAsync("query", "OfficeSecurityAgent", allowFailure: true), StringComparison.Ordinal); // service does not exist

        // 10. Uninstalling gave the computer back its normal behaviour.
        if (OperatingSystem.IsWindows() && _blockedCurl is not null)
        {
            Assert.Null(HklmValue(UsbKey, "Deny_Read"));
            Assert.Null(HklmValue(@"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist", "1"));
            Assert.Null(HklmValue(@"SOFTWARE\Policies\Microsoft\Windows\Installer", "DisableMSI"));
            Assert.Null(new WindowsFirewall().Find(FirewallEnforcer.RuleName(_blockedCurl)));
            output.WriteLine("After uninstall: USB, website, installation and firewall settings made by the agent are gone.");
        }
    }

    private const string UsbKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";

    private string? _blockedCurl;
    private FirewallProfiles _firewallWasOff;

    private async Task EnforcementAsync(HttpClient admin, Guid policyId, Guid computerId)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // A copy of Windows' curl.exe that the policy blocks from the network; the original stays allowed.
        var curl = Path.Combine(Environment.SystemDirectory, "curl.exe");
        var folder = Directory.CreateTempSubdirectory("ocss-fw-").FullName;
        _blockedCurl = Path.Combine(folder, "curl-blocked.exe");
        File.Copy(curl, _blockedCurl);

        // The build machine's firewall may be switched off; the agent never switches it on, so the test does.
        _firewallWasOff = new WindowsFirewall().DisabledProfiles();
        if (_firewallWasOff != FirewallProfiles.None)
        {
            output.WriteLine($"Test machine: turning on Windows Firewall for {_firewallWasOff} (restored at the end).");
            await RunAsync("netsh.exe", "advfirewall", "set", "allprofiles", "state", "on");
        }

        await SavePolicyAsync(admin, policyId, s => s with
        {
            RemovableStorage = new RemovableStorageSettings { Mode = EnforcementMode.Enforce, BlockPortableDevices = true, BlockOpticalDrives = true },
            SoftwareInstallation = new SoftwareInstallationSettings { BlockStaffInstalls = true },
            Browser = new BrowserSettings { BlockedUrls = ["example.com"], DisablePrivateBrowsing = true },
            Network = new NetworkSettings { BlockedApplicationPaths = [_blockedCurl] },
        });

        var detail = await WaitForControlsAsync(admin, computerId, "all controls applied and verified", c =>
            c[SecurityControl.RemovableStorage] == ControlState.Enforced && c[SecurityControl.MobileDeviceTransfer] == ControlState.Enforced
            && c[SecurityControl.SoftwareInstallation] == ControlState.PartiallyEnforced && c[SecurityControl.BrowserRestrictions] == ControlState.Enforced
            && c[SecurityControl.NetworkRestrictions] == ControlState.Enforced && c[SecurityControl.AgentTamperProtection] == ControlState.Enforced);
        foreach (var control in detail.Controls.Where(c => c.State != ControlState.NotImplemented && c.State != ControlState.NotConfigured))
        {
            output.WriteLine($"  {control.Control}: {control.State} — {control.Details}");
        }

        // The Windows settings are really there.
        Assert.Equal(1, HklmValue(UsbKey, "Deny_Read"));
        Assert.Equal(1, HklmValue(UsbKey, "Deny_Execute"));
        Assert.Equal("example.com", HklmValue(@"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist", "1"));
        Assert.Equal(1, HklmValue(@"SOFTWARE\Policies\Microsoft\Windows\Installer", "DisableMSI"));

        // Effect 1: Microsoft Edge refuses the blocked site but still opens others.
        var edge = new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles }
            .Select(f => Path.Combine(Environment.GetFolderPath(f), @"Microsoft\Edge\Application\msedge.exe")).FirstOrDefault(File.Exists);
        Assert.True(edge is not null, "Microsoft Edge is not installed on the test machine.");
        // example.com and example.org serve the same "Example Domain" page; only example.com is on the blocked list.
        var blockedPage = await EdgeDomAsync(edge, "https://example.com/");
        var allowedPage = await EdgeDomAsync(edge, "https://example.org/");
        output.WriteLine($"Edge, blocked site (example.com): {Snippet(blockedPage)}");
        output.WriteLine($"Edge, allowed site (example.org): {Snippet(allowedPage)}");
        Assert.Contains("Example Domain", allowedPage, StringComparison.Ordinal);
        Assert.DoesNotContain("Example Domain", blockedPage, StringComparison.Ordinal);
        Assert.True(blockedPage.Length > 0, "Edge returned nothing for the blocked site.");

        // Effect 2: the blocked program cannot reach the internet; the same program elsewhere can.
        var blockedExit = await RunAsync(_blockedCurl, "-sS", "-o", "NUL", "--max-time", "20", "https://www.microsoft.com/");
        var allowedExit = await RunAsync(curl, "-sS", "-o", "NUL", "--max-time", "20", "https://www.microsoft.com/");
        output.WriteLine($"Firewall: blocked program exit code {blockedExit}, allowed program exit code {allowedExit}");
        Assert.NotEqual(0, blockedExit);
        Assert.Equal(0, allowedExit);

        // Tampering 1: an administrator deletes the USB block by hand -> restored and reported.
        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(UsbKey, writable: true)!)
        {
            key.DeleteValue("Deny_Read");
        }

        await WaitForAsync(() => Task.FromResult(HklmValue(UsbKey, "Deny_Read") is 1 ? (bool?)true : null), TimeSpan.FromSeconds(120), "deleted USB setting restored by the agent");

        // Tampering 2: someone lets every signed-in user stop the service -> restored and reported.
        // Insert an extra "allow start/stop" entry for interactive users at the start of the permission list (D:).
        var sddl = (await ScAsync("sdshow", "OfficeSecurityAgent")).Split('\n').Select(l => l.Trim()).Last(l => l.Contains("D:", StringComparison.Ordinal));
        var weak = sddl.Replace("D:", "D:(A;;RPWP;;;IU)", StringComparison.Ordinal);
        await RunAsync(Path.Combine(Environment.SystemDirectory, "sc.exe"), "sdset", "OfficeSecurityAgent", weak);
        Assert.Contains("(A;;RPWP;;;IU)", await ScAsync("sdshow", "OfficeSecurityAgent"), StringComparison.Ordinal);
        await WaitForAsync(async () => (await ScAsync("sdshow", "OfficeSecurityAgent")).Contains("(A;;RPWP;;;IU)", StringComparison.Ordinal) ? null : (bool?)true,
            TimeSpan.FromSeconds(120), "weakened service permissions restored by the agent");

        var tamper = await WaitForAsync(async () =>
        {
            var e = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?computerId={computerId}&pageSize=200");
            var alerts = e!.Items.Where(x => x.EventType == nameof(SecurityEventType.PolicyTamperAttempt) && x.Severity == EventSeverities.Critical).ToList();
            return alerts.Any(a => a.Details!.Contains("USB drive blocking", StringComparison.Ordinal)) && alerts.Any(a => a.Details!.Contains("service settings", StringComparison.Ordinal)) ? alerts : null;
        }, TimeSpan.FromSeconds(90), "tampering alerts received by the server");
        output.WriteLine($"Tampering alerts: {tamper.Count}");

        // Temporary exception: USB drives allowed for this computer, then ended early.
        var exemption = await (await admin.PostAsJsonAsync(ApiRoutes.ComputerExemptions(computerId),
            new CreateExemptionRequest(nameof(SecurityControl.RemovableStorage), "End-to-end test", 30))).EnsureSuccessStatusCode().Content.ReadFromJsonAsync<ExemptionResponse>();
        await WaitForControlsAsync(admin, computerId, "USB drives temporarily allowed", c => c[SecurityControl.RemovableStorage] == ControlState.TemporarilyAllowed);
        Assert.Null(HklmValue(UsbKey, "Deny_Read"));
        Assert.Equal(1, HklmValue(@$"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{{6AC27878-A6FA-4155-BA85-F98F491D4F33}}", "Deny_Read")); // phones still blocked
        (await admin.DeleteAsync(new Uri(ApiRoutes.ComputerExemptionById(computerId, exemption!.Id), UriKind.Relative))).EnsureSuccessStatusCode();
        await WaitForControlsAsync(admin, computerId, "USB blocking back after the exception ended", c => c[SecurityControl.RemovableStorage] == ControlState.Enforced);
        Assert.Equal(1, HklmValue(UsbKey, "Deny_Read"));
    }

    private const string TestUser = "ocsstest";

    private async Task Part2Async(HttpClient admin, Guid policyId, Guid computerId)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // Test material: a company folder with a file, a probe program (a copy of an unsigned program) in a user
        // folder and in Program Files, and a local Windows account.
        var company = Directory.CreateDirectory(@"C:\OcssTest\Company").FullName;
        var document = Path.Combine(company, "salaries.txt");
        File.WriteAllText(document, "confidential");
        var agentExe = Environment.GetEnvironmentVariable(WindowsServiceFactAttribute.AgentExeVariable)!;
        var userProbe = Path.Combine(Directory.CreateTempSubdirectory("ocss-appctl-").FullName, "probe.exe");
        File.Copy(agentExe, userProbe);
        var installedProbe = Path.Combine(Directory.CreateDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OcssProbe")).FullName, "probe.exe");
        File.Copy(agentExe, installedProbe, overwrite: true);
        var password = "Ocss-" + Guid.NewGuid().ToString("N")[..12] + "!9";
        Assert.Equal(0, await RunAsync("net.exe", "user", TestUser, password, "/add"));

        // Folders this CI machine needs while Application Control is enforced (the test program and the build runner).
        var runner = Process.GetProcessesByName("Runner.Worker").Select(p => Path.GetDirectoryName(Path.GetDirectoryName(p.MainModule!.FileName))).FirstOrDefault();
        var ciFolders = new[] { AppContext.BaseDirectory.TrimEnd('\\') + @"\*", runner is null ? null : runner + @"\*" }.OfType<string>().ToList();
        output.WriteLine("Extra allowed folders for the CI machine: " + string.Join("; ", ciFolders));

        await SavePolicyAsync(admin, policyId, s => s with
        {
            SignInAudit = new SignInAuditSettings { RecordWindowsSignIns = true },
            FileProtection = new FileProtectionSettings { ProtectedFolders = [new ProtectedFolder(company, AuditAccess: true, ControlledFolderAccess: true)] },
            DiskEncryption = new DiskEncryptionSettings { RequireBitLocker = true },
            ApplicationControl = new ApplicationControlSettings { Mode = EnforcementMode.Audit, AllowedFolders = ciFolders },
        });

        var detail = await WaitForControlsAsync(admin, computerId, "part 2 controls applied", c =>
            c[SecurityControl.LoginAudit] == ControlState.Enforced && c[SecurityControl.FileAccessAudit] == ControlState.Enforced
            && c[SecurityControl.ApplicationControl] == ControlState.AuditOnly
            && c[SecurityControl.ControlledFolderAccess] is ControlState.Enforced or ControlState.NotSupportedOnEdition or ControlState.PartiallyEnforced
            && c[SecurityControl.DiskEncryption] is not ControlState.Unknown and not ControlState.NotImplemented and not ControlState.NotConfigured);
        foreach (var control in detail.Controls.Where(c => c.Control is SecurityControl.LoginAudit or SecurityControl.FileAccessAudit or SecurityControl.ApplicationControl
                     or SecurityControl.ControlledFolderAccess or SecurityControl.DiskEncryption))
        {
            output.WriteLine($"  {control.Control}: {control.State} — {control.Details}");
        }

        // Sign-in records: one failed and one successful Windows sign-in of the test account.
        Assert.False(TryLogon(TestUser, "wrong-password"));
        Assert.True(TryLogon(TestUser, password), "The test account could not sign in.");
        await WaitForEventAsync(admin, computerId, SecurityEventType.FailedLogin, TestUser, "failed Windows sign-in reported");
        await WaitForEventAsync(admin, computerId, SecurityEventType.SuccessfulLogin, TestUser, "successful Windows sign-in reported");

        // File access records.
        _ = File.ReadAllText(document);
        await WaitForEventAsync(admin, computerId, SecurityEventType.ProtectedFileAccess, "salaries.txt", "file access in the protected folder reported");

        // Application Control, audit mode: the probe still runs and is reported as "would be blocked".
        Assert.Equal(0, await RunAsync(userProbe, "help"));
        await WaitForEventAsync(admin, computerId, SecurityEventType.UnauthorizedApplicationBlocked, "probe.exe", "audit-mode report for the probe program");

        // Enforce: the probe in the user folder is refused; the copy in Program Files runs.
        await SavePolicyAsync(admin, policyId, s => s with { ApplicationControl = s.ApplicationControl with { Mode = EnforcementMode.Enforce } });
        await WaitForControlsAsync(admin, computerId, "Application Control enforced", c => c[SecurityControl.ApplicationControl] == ControlState.Enforced);
        var blocked = await TryRunAsync(userProbe, "help");
        var allowed = await TryRunAsync(installedProbe, "help");
        output.WriteLine($"Application Control enforced: user-folder program → {blocked}; Program Files program → {allowed}");
        Assert.NotEqual("exit 0", blocked);
        Assert.Equal("exit 0", allowed);
        await WaitForEventAsync(admin, computerId, SecurityEventType.UnauthorizedApplicationBlocked, "Blocked by Application Control", "block reported");

        // The agent itself still starts under enforcement.
        await ScAsync("stop", "OfficeSecurityAgent");
        await WaitForAsync(async () => (await ScAsync("query", "OfficeSecurityAgent")).Contains("STOPPED", StringComparison.Ordinal) ? (bool?)true : null, TimeSpan.FromSeconds(60), "service stopped");
        await ScAsync("start", "OfficeSecurityAgent");
        await WaitForAsync(async () => await ServicePidAsync() is not 0 ? (bool?)true : null, TimeSpan.FromSeconds(60), "service running again under Application Control");
        await WaitForControlsAsync(admin, computerId, "agent reporting again after the restart", c => c[SecurityControl.ApplicationControl] == ControlState.Enforced);

        // Off: the policy is removed again.
        await SavePolicyAsync(admin, policyId, s => s with { ApplicationControl = new ApplicationControlSettings() });
        await WaitForControlsAsync(admin, computerId, "Application Control switched off", c => c[SecurityControl.ApplicationControl] == ControlState.NotConfigured);
        var afterOff = await TryRunAsync(userProbe, "help");
        output.WriteLine($"After switching Application Control off: user-folder program → {afterOff}");
        Assert.Equal("exit 0", afterOff);
    }

    private async Task WaitForEventAsync(HttpClient admin, Guid computerId, SecurityEventType type, string contains, string what) =>
        await WaitForAsync(async () =>
        {
            var e = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?computerId={computerId}&pageSize=200");
            var match = e!.Items.FirstOrDefault(x => x.EventType == type.ToString() && x.Details!.Contains(contains, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                output.WriteLine($"  event {match.EventType} ({match.Severity}): {match.Details}");
            }

            return match;
        }, TimeSpan.FromSeconds(120), what);

    private static async Task<string> TryRunAsync(string exe, params string[] arguments)
    {
        try
        {
            var start = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)!;
            _ = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(2));
            return $"exit {process.ExitCode}";
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return $"refused by Windows: {ex.Message} ({ex.NativeErrorCode})";
        }
    }

    private static bool TryLogon(string user, string password)
    {
        if (!LogonUser(user, ".", password, 2 /* interactive */, 0, out var token))
        {
            return false;
        }

        CloseHandle(token);
        return true;
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private async Task<ComputerDetail> WaitForControlsAsync(HttpClient admin, Guid computerId, string what, Func<IReadOnlyDictionary<SecurityControl, ControlState>, bool> condition) =>
        await WaitForAsync(async () =>
        {
            var d = await admin.GetFromJsonAsync<ComputerDetail>(ApiRoutes.ComputerById(computerId));
            var states = d!.Controls.ToDictionary(c => c.Control, c => c.State);
            return states.Count > 0 && condition(states) ? d : null;
        }, TimeSpan.FromSeconds(150), what);

    /// <summary>The visible text of a page, shortened for the test log.</summary>
    private static string Snippet(string html)
    {
        var text = System.Text.RegularExpressions.Regex.Replace(System.Text.RegularExpressions.Regex.Replace(html, "<(script|style)[^>]*>.*?</\\1>", " ",
            System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.IgnoreCase), "<[^>]+>", " ");
        text = System.Text.RegularExpressions.Regex.Replace(text, "\\s+", " ").Trim();
        return text.Length > 400 ? text[..400] + "…" : text;
    }

    private static async Task<string> EdgeDomAsync(string edge, string url)
    {
        var profile = Directory.CreateTempSubdirectory("ocss-edge-").FullName;
        var start = new ProcessStartInfo(edge) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in new[] { "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", $"--user-data-dir={profile}", "--dump-dom", url })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        _ = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(90));
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
        }

        return await stdout;
    }

    private void RestoreFirewall()
    {
        foreach (var (profile, name) in new[] { (FirewallProfiles.Domain, "domainprofile"), (FirewallProfiles.Private, "privateprofile"), (FirewallProfiles.Public, "publicprofile") })
        {
            if (_firewallWasOff.HasFlag(profile))
            {
                using var p = Process.Start(new ProcessStartInfo("netsh.exe", $"advfirewall set {name} state off") { UseShellExecute = false, CreateNoWindow = true })!;
                p.WaitForExit();
            }
        }
    }

    private static object? HklmValue(string key, string name)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key);
        return k?.GetValue(name);
    }

    private async Task InstallTestMsiAsync(HttpClient admin, Guid computerId)
    {
        var msi = Environment.GetEnvironmentVariable(WindowsServiceFactAttribute.TestMsiVariable);
        Assert.True(msi is { Length: > 0 } && File.Exists(msi), $"Set {WindowsServiceFactAttribute.TestMsiVariable} to the test MSI.");
        var bytes = await File.ReadAllBytesAsync(msi);
        const string name = "OCSS Test Package";
        var title = await (await admin.PostAsJsonAsync(ApiRoutes.ApprovedSoftware, new SaveApprovedSoftwareRequest(name, "Office Security Tests", null)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<ApprovedSoftwareResponse>();

        async Task<DeploymentResponse> DeployAsync(bool requireSignature)
        {
            var query = requireSignature ? "&signerSubject=CN%3DContoso%20Ltd&allowUnsigned=false" : "&allowUnsigned=true";
            using var body = new ByteArrayContent(bytes);
            var package = await (await admin.PostAsync(new Uri($"{ApiRoutes.ApprovedSoftwarePackages(title!.Id)}?fileName=ocss-test.msi&installerType=Msi{query}", UriKind.Relative), body))
                .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SoftwarePackageResponse>();
            var job = Assert.Single((await (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package!.Id, [computerId])))
                .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<List<DeploymentResponse>>())!);
            return await WaitForAsync(async () =>
            {
                var list = await admin.GetFromJsonAsync<PagedResult<DeploymentResponse>>($"{ApiRoutes.SoftwareDeployments}?computerId={computerId}");
                return list!.Items.Single(d => d.Id == job.Id) is { FinishedAtUtc: not null } done ? done : null;
            }, TimeSpan.FromMinutes(5), requireSignature ? "installation requiring a signature finished" : "installation finished");
        }

        // a) The test MSI has no signature: when the administrator required a signed installer, it is not run.
        var refused = await DeployAsync(requireSignature: true);
        output.WriteLine($"Signed-only installer: {refused.Status} - {refused.Message}");
        Assert.Equal(JobStatuses.Failed, refused.Status);
        Assert.Contains("no digital signature", refused.Message, StringComparison.Ordinal);

        // b) Allowed unsigned: msiexec installs it silently and the new program appears in the inventory.
        var installed = await DeployAsync(requireSignature: false);
        output.WriteLine($"Unsigned allowed: {installed.Status} (exit code {installed.ExitCode}) - {installed.Message}");
        Assert.Equal(JobStatuses.Succeeded, installed.Status);
        Assert.Equal(0, installed.ExitCode);

        var seen = await WaitForAsync(async () =>
            (await admin.GetFromJsonAsync<List<InstalledSoftwareResponse>>($"{ApiRoutes.SoftwareInventoryComputers}?computerId={computerId}"))!
                .FirstOrDefault(s => s.Name == name), TimeSpan.FromSeconds(90), "installed program reported in inventory");
        Assert.True(seen.IsApproved);
        Assert.Equal("1.0.0", seen.Version);

        var events = await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?computerId={computerId}&pageSize=200");
        Assert.Contains(events!.Items, e => e.EventType == nameof(SecurityEventType.SoftwareInstalled) && e.Details!.Contains(name, StringComparison.Ordinal));
        Assert.Contains(events.Items, e => e.EventType == nameof(SecurityEventType.PolicyTamperAttempt) && e.Severity == EventSeverities.Critical);
    }

    private static async Task SavePolicyAsync(HttpClient admin, Guid id, Func<PolicySettings, PolicySettings> change)
    {
        var detail = await admin.GetFromJsonAsync<PolicyDetail>(ApiRoutes.PolicyById(id));
        (await admin.PutAsJsonAsync(ApiRoutes.PolicyById(id), new SavePolicyRequest(detail!.Name, detail.Description, change(detail.Settings)))).EnsureSuccessStatusCode();
    }

    private async Task<T> WaitForAsync<T>(Func<Task<T?>> probe, TimeSpan timeout, string what)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            if (await probe() is { } value)
            {
                output.WriteLine($"{what}: after {watch.Elapsed.TotalSeconds:0} s");
                return value;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        throw new TimeoutException($"Timed out waiting for: {what}");
    }

    private async Task<int> RunAsync(string exe, params string[] arguments)
    {
        var start = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(3));
        output.WriteLine($"> agent {arguments[0]} (exit {process.ExitCode})\n{await stdout}{await stderr}");
        return process.ExitCode;
    }

    private static async Task<string> ScAsync(string command, string service, bool allowFailure = false)
    {
        var start = new ProcessStartInfo("sc.exe") { RedirectStandardOutput = true, UseShellExecute = false };
        start.ArgumentList.Add(command);
        start.ArgumentList.Add(service);
        using var process = Process.Start(start)!;
        var text = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0 && !allowFailure)
        {
            throw new InvalidOperationException($"sc {command} failed: {text}");
        }

        return text;
    }

    private static async Task<int> ServicePidAsync()
    {
        var text = await ScAsync("queryex", "OfficeSecurityAgent");
        var match = PidRegex().Match(text);
        return match.Success && text.Contains("RUNNING", StringComparison.Ordinal) ? int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture) : 0;
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    [GeneratedRegex(@"PID\s*:\s*(\d+)")]
    private static partial Regex PidRegex();
}
