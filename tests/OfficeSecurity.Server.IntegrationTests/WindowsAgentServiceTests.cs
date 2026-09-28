using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.RegularExpressions;
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
            Assert.All(online.Controls, c => Assert.Equal(ControlState.NotImplemented, c.State));
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

            // 8. Approved software installation with the real Windows installer (msiexec) and signature check.
            await InstallTestMsiAsync(admin, pending.Id);
        }
        finally
        {
            var uninstall = await RunAsync(exe, "uninstall");
            Assert.Equal(0, uninstall);
            if (Environment.GetEnvironmentVariable(WindowsServiceFactAttribute.TestMsiVariable) is { Length: > 0 } msi && File.Exists(msi))
            {
                await RunAsync(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), "/x", msi, "/qn", "/norestart");
            }
        }

        Assert.Contains("1060", await ScAsync("query", "OfficeSecurityAgent", allowFailure: true), StringComparison.Ordinal); // service does not exist
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
