using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class SoftwareManagementTests
{
    private static readonly byte[] InstallerBytes = [.. Enumerable.Range(0, 200_000).Select(i => (byte)(i * 7 % 256))];

    private static async Task<ApprovedSoftwareResponse> ApproveTitleAsync(HttpClient admin, string name = "Contoso Viewer", string? publisher = "Contoso Ltd")
    {
        var response = await admin.PostAsJsonAsync(ApiRoutes.ApprovedSoftware, new SaveApprovedSoftwareRequest(name, publisher, "For reading reports"));
        return (await response.EnsureSuccessStatusCode().Content.ReadFromJsonAsync<ApprovedSoftwareResponse>())!;
    }

    private static Task<HttpResponseMessage> UploadAsync(HttpClient admin, Guid approvedId, string fileName = "viewer.msi", string type = InstallerTypes.Msi,
        string? silent = null, string? signer = "CN=Contoso Ltd", bool allowUnsigned = false, byte[]? content = null)
    {
        var query = $"?fileName={Uri.EscapeDataString(fileName)}&installerType={type}&allowUnsigned={allowUnsigned}"
            + (silent is null ? string.Empty : $"&silentArguments={Uri.EscapeDataString(silent)}")
            + (signer is null ? string.Empty : $"&signerSubject={Uri.EscapeDataString(signer)}");
        var body = new ByteArrayContent(content ?? InstallerBytes);
        body.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return admin.PostAsync(new Uri(ApiRoutes.ApprovedSoftwarePackages(approvedId) + query, UriKind.Relative), body);
    }

    private static async Task<SoftwarePackageResponse> UploadPackageAsync(HttpClient admin, Guid approvedId) =>
        (await (await UploadAsync(admin, approvedId)).EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SoftwarePackageResponse>())!;

    private static async Task<List<DeploymentResponse>> DeploymentsAsync(HttpClient admin, Guid computerId) =>
        (await admin.GetFromJsonAsync<PagedResult<DeploymentResponse>>($"{ApiRoutes.SoftwareDeployments}?computerId={computerId}"))!.Items.ToList();

    private static async Task<List<SecurityEventResponse>> EventsAsync(HttpClient admin, Guid computerId, SecurityEventType type) =>
        (await admin.GetFromJsonAsync<PagedResult<SecurityEventResponse>>($"{ApiRoutes.Events}?computerId={computerId}&pageSize=200"))!
            .Items.Where(e => e.EventType == type.ToString()).ToList();

    /// <summary>An HTTP client that presents the given agent's certificate (as mutual TLS would).</summary>
    private static HttpClient AgentClient(ServerFactory server, AgentHarness agent) =>
        new(new CertificateHeaderHandler(X509Certificate2.CreateFromPem(agent.Config.Load().CertificatePem!)) { InnerHandler = server.Server.CreateHandler() })
        {
            BaseAddress = server.Server.BaseAddress,
        };

    [Fact]
    public async Task Approved_catalog_and_installer_upload_are_validated_and_fingerprinted()
    {
        await using var server = new ServerFactory();
        using var admin = server.Client(await server.OwnerTokenAsync());

        var title = await ApproveTitleAsync(admin);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync(ApiRoutes.ApprovedSoftware, new SaveApprovedSoftwareRequest("Contoso Viewer", null, null))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(ApiRoutes.ApprovedSoftware, new SaveApprovedSoftwareRequest(" ", null, null))).StatusCode);

        // Invalid uploads.
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(admin, title.Id, fileName: "viewer.exe")).StatusCode); // type mismatch
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(admin, title.Id, fileName: "setup.exe", type: InstallerTypes.Exe)).StatusCode); // no silent options
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(admin, title.Id, signer: null)).StatusCode); // unsigned not allowed
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(admin, title.Id, fileName: @"..\viewer.msi")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(admin, title.Id, content: [])).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await UploadAsync(admin, Guid.NewGuid())).StatusCode);

        var package = await UploadPackageAsync(admin, title.Id);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(InstallerBytes)), package.Sha256);
        Assert.Equal(InstallerBytes.Length, package.SizeBytes);
        Assert.Equal("CN=Contoso Ltd", package.SignerSubject);

        var exe = await UploadAsync(admin, title.Id, fileName: "setup.exe", type: InstallerTypes.Exe, silent: "/S", signer: null, allowUnsigned: true);
        Assert.Equal(HttpStatusCode.OK, exe.StatusCode);

        var catalog = await admin.GetFromJsonAsync<List<ApprovedSoftwareResponse>>(ApiRoutes.ApprovedSoftware);
        Assert.Equal(2, Assert.Single(catalog!).Packages.Count);

        // A title with installers cannot be removed; an unused installer can.
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync(new Uri(ApiRoutes.ApprovedSoftwareById(title.Id), UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync(new Uri(ApiRoutes.SoftwarePackageById(package.Id), UriKind.Relative))).StatusCode);
        Assert.False(File.Exists(Path.Combine(server.DataDirectory, "packages", package.Id.ToString("N") + ".pkg")));

        var audit = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"{ApiRoutes.Audit}?pageSize=200");
        Assert.Contains(audit!.Items, a => a.Action == "software.upload-package" && a.Details!.Contains(package.Sha256, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Staff_request_approved_by_an_administrator_is_installed_by_the_agent_on_that_computer()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        var title = await ApproveTitleAsync(admin);
        var package = await UploadPackageAsync(admin, title.Id);

        // The staff member signs in on the managed computer and asks for the program.
        await server.CreateActiveStaffAsync(owner, "EMP800", "Staff member pass 2026");
        using var anonymous = server.Client();
        var ticket = await agent.Runtime.GetLoginTicketAsync(CancellationToken.None);
        var session = await (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP800", "Staff member pass 2026", ticket)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SessionResponse>();
        using var staff = server.Client(session!.Token);

        Assert.Equal(HttpStatusCode.BadRequest, (await staff.PostAsJsonAsync(ApiRoutes.SoftwareRequests, new CreateSoftwareRequest("Contoso Viewer", ""))).StatusCode);
        var created = await (await staff.PostAsJsonAsync(ApiRoutes.SoftwareRequests, new CreateSoftwareRequest("Contoso Viewer", "I need to open client reports.")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SoftwareRequestResponse>();
        Assert.Equal(SoftwareRequestStatuses.Pending, created!.Status);
        Assert.Equal(agent.ComputerId, created.ComputerId);

        var overview = await admin.GetFromJsonAsync<DashboardOverviewResponse>(ApiRoutes.DashboardOverview);
        Assert.Equal(1, overview!.PendingSoftwareRequests);

        var pending = await admin.GetFromJsonAsync<PagedResult<SoftwareRequestResponse>>($"{ApiRoutes.SoftwareRequests}?status=Pending");
        Assert.Equal(created.Id, Assert.Single(pending!.Items).Id);

        var approved = await (await admin.PostAsJsonAsync(ApiRoutes.SoftwareRequestApprove(created.Id), new ApproveSoftwareRequest(package.Id, null, "OK")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SoftwareRequestResponse>();
        Assert.Equal(SoftwareRequestStatuses.Approved, approved!.Status);
        Assert.Equal(JobStatuses.Queued, approved.InstallStatus);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync(ApiRoutes.SoftwareRequestReject(created.Id), new RejectSoftwareRequest("no"))).StatusCode);

        // The agent picks the job up at its next check-in, downloads exactly the uploaded file and runs it.
        await agent.RunUntilAsync(() => agent.Runner.Runs.Count > 0);
        var run = Assert.Single(agent.Runner.Runs);
        Assert.Equal(InstallerBytes, run.Content);
        Assert.Equal("Contoso Viewer", run.Job.SoftwareName);

        var deployment = Assert.Single(await DeploymentsAsync(admin, agent.ComputerId));
        Assert.Equal(JobStatuses.Succeeded, deployment.Status);
        Assert.Equal(1, deployment.Attempts);
        Assert.Equal(created.Id, deployment.RequestId);

        var mine = await staff.GetFromJsonAsync<List<SoftwareRequestResponse>>(ApiRoutes.MySoftwareRequests);
        Assert.Equal(JobStatuses.Succeeded, Assert.Single(mine!).InstallStatus);
        Assert.Single(await EventsAsync(admin, agent.ComputerId, SecurityEventType.SoftwareDeployment));

        // Later check-ins do not install it again.
        server.Clock.Advance(TimeSpan.FromMinutes(5));
        await agent.StepAsync();
        Assert.Single(agent.Runner.Runs);
    }

    [Fact]
    public async Task Rejected_request_shows_the_note_and_installs_nothing()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        var (_, token) = await server.CreateActiveStaffAsync(owner, "EMP801", "Staff member pass 2026");
        using var staff = server.Client(token);

        var created = await (await staff.PostAsJsonAsync(ApiRoutes.SoftwareRequests, new CreateSoftwareRequest("Some Game", "For breaks between calls.")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SoftwareRequestResponse>();
        Assert.Null(created!.ComputerId); // signed in without the agent's ticket

        // Approval needs an approved computer; this request came from no managed computer.
        var title = await ApproveTitleAsync(admin);
        var package = await UploadPackageAsync(admin, title.Id);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(ApiRoutes.SoftwareRequestApprove(created.Id), new ApproveSoftwareRequest(package.Id, null, null))).StatusCode);

        var rejected = await (await admin.PostAsJsonAsync(ApiRoutes.SoftwareRequestReject(created.Id), new RejectSoftwareRequest("Not needed for work.")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SoftwareRequestResponse>();
        Assert.Equal(SoftwareRequestStatuses.Rejected, rejected!.Status);

        var mine = Assert.Single((await staff.GetFromJsonAsync<List<SoftwareRequestResponse>>(ApiRoutes.MySoftwareRequests))!);
        Assert.Equal("Not needed for work.", mine.ReviewNote);
        Assert.Null(mine.InstallStatus);
        Assert.Empty((await admin.GetFromJsonAsync<PagedResult<DeploymentResponse>>(ApiRoutes.SoftwareDeployments))!.Items);
    }

    [Fact]
    public async Task Deployments_go_only_to_approved_computers_and_can_be_cancelled_before_they_start()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var trusted = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        using var waiting = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner));
        await waiting.StepAsync();
        var package = await UploadPackageAsync(admin, (await ApproveTitleAsync(admin)).Id);

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, [waiting.ComputerId]))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, []))).StatusCode);

        var jobs = await (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, [trusted.ComputerId])))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<List<DeploymentResponse>>();
        var job = Assert.Single(jobs!);

        // Asking again while it is still queued does not create a second installation.
        var again = await (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, [trusted.ComputerId])))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<List<DeploymentResponse>>();
        Assert.Equal(job.Id, Assert.Single(again!).Id);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync(new Uri(ApiRoutes.DeploymentCancel(job.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync(new Uri(ApiRoutes.DeploymentCancel(job.Id), UriKind.Relative), null)).StatusCode);

        server.Clock.Advance(TimeSpan.FromMinutes(5));
        await trusted.StepAsync();
        Assert.Empty(trusted.Runner.Runs);
        Assert.Equal(JobStatuses.Cancelled, Assert.Single(await DeploymentsAsync(admin, trusted.ComputerId)).Status);

        // The used installer is kept for the record.
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync(new Uri(ApiRoutes.SoftwarePackageById(package.Id), UriKind.Relative))).StatusCode);
    }

    [Fact]
    public async Task Failed_installation_is_reported_as_a_warning()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        agent.Runner.Outcome = new Agent.Core.InstallerOutcome(JobStatuses.Failed, 1603, "The installer reported a fatal error (1603).");
        var package = await UploadPackageAsync(admin, (await ApproveTitleAsync(admin)).Id);
        (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, [agent.ComputerId]))).EnsureSuccessStatusCode();

        await agent.RunUntilAsync(() => agent.Runner.Runs.Count > 0);

        var deployment = Assert.Single(await DeploymentsAsync(admin, agent.ComputerId));
        Assert.Equal(JobStatuses.Failed, deployment.Status);
        Assert.Equal(1603, deployment.ExitCode);
        Assert.Equal(EventSeverities.Warning, Assert.Single(await EventsAsync(admin, agent.ComputerId, SecurityEventType.SoftwareDeployment)).Severity);
    }

    [Fact]
    public async Task Installer_that_fails_the_signature_check_is_not_run_and_raises_a_critical_event()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var agent = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        agent.Verifier.Result = new Client.Core.SignatureCheck(Client.Core.SignatureState.Valid, "CN=Unknown Publisher", null);
        var package = await UploadPackageAsync(admin, (await ApproveTitleAsync(admin)).Id);
        (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, [agent.ComputerId]))).EnsureSuccessStatusCode();

        for (var i = 0; i < 10 && (await DeploymentsAsync(admin, agent.ComputerId)).Single().Status != JobStatuses.Failed; i++)
        {
            await agent.StepAsync();
            server.Clock.Advance(TimeSpan.FromSeconds(61));
        }

        var deployment = Assert.Single(await DeploymentsAsync(admin, agent.ComputerId));
        Assert.Equal(JobStatuses.Failed, deployment.Status);
        Assert.Contains("Unknown Publisher", deployment.Message, StringComparison.Ordinal);
        Assert.Empty(agent.Runner.Runs);

        // The alert reaches the server with the event upload.
        await agent.StepAsync();
        var alert = Assert.Single(await EventsAsync(admin, agent.ComputerId, SecurityEventType.PolicyTamperAttempt));
        Assert.Equal(EventSeverities.Critical, alert.Severity);
    }

    [Fact]
    public async Task Agents_can_only_fetch_their_own_started_jobs_and_give_up_after_three_attempts()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var pcA = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        using var pcB = await ComputerLifecycleTests.EnrolledAgentAsync(server, owner, admin);
        var package = await UploadPackageAsync(admin, (await ApproveTitleAsync(admin)).Id);
        var job = Assert.Single((await (await admin.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(package.Id, [pcA.ComputerId])))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<List<DeploymentResponse>>())!);

        using var a = AgentClient(server, pcA);
        using var b = AgentClient(server, pcB);

        Assert.Empty((await b.GetFromJsonAsync<List<AgentJob>>(ApiRoutes.AgentJobs))!);
        Assert.Single((await a.GetFromJsonAsync<List<AgentJob>>(ApiRoutes.AgentJobs))!);

        // Not started yet: no download, even for the right computer.
        Assert.Equal(HttpStatusCode.NotFound, (await a.GetAsync(new Uri(ApiRoutes.AgentJobPackage(job.Id), UriKind.Relative))).StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await b.PostAsync(new Uri(ApiRoutes.AgentJobStart(job.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await a.PostAsync(new Uri(ApiRoutes.AgentJobStart(job.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync(new Uri(ApiRoutes.AgentJobPackage(job.Id), UriKind.Relative))).StatusCode);
        Assert.Equal(InstallerBytes, await a.GetByteArrayAsync(new Uri(ApiRoutes.AgentJobPackage(job.Id), UriKind.Relative)));
        Assert.Equal(HttpStatusCode.NotFound, (await b.PostAsJsonAsync(ApiRoutes.AgentJobResult(job.Id), new AgentJobResult(JobStatuses.Succeeded, 0, null))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await a.PostAsJsonAsync(ApiRoutes.AgentJobResult(job.Id), new AgentJobResult(JobStatuses.Cancelled, 0, null))).StatusCode);

        // Interrupted twice more (e.g. the computer restarted during installation): the fourth start is refused.
        Assert.Equal(HttpStatusCode.NoContent, (await a.PostAsync(new Uri(ApiRoutes.AgentJobStart(job.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await a.PostAsync(new Uri(ApiRoutes.AgentJobStart(job.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await a.PostAsync(new Uri(ApiRoutes.AgentJobStart(job.Id), UriKind.Relative), null)).StatusCode);
        Assert.Equal(JobStatuses.Failed, Assert.Single(await DeploymentsAsync(admin, pcA.ComputerId)).Status);
        Assert.Empty((await a.GetFromJsonAsync<List<AgentJob>>(ApiRoutes.AgentJobs))!);
    }

    [Fact]
    public async Task Software_inventory_sets_a_baseline_then_reports_installs_and_removals()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        await ApproveTitleAsync(admin, "Microsoft Office", "Microsoft Corporation");
        using var agent = new AgentHarness(server, await server.CreateEnrollmentCodeAsync(owner));
        agent.Inventory.Software.Add(new InstalledSoftware("Microsoft Office Professional Plus 2021", "16.0.1", "Microsoft Corporation", null, "Machine"));
        agent.Inventory.Software.Add(new InstalledSoftware("Old Tool", "1.0", "Tools Inc", null, "Machine"));
        await agent.StepAsync();
        (await admin.PostAsync(new Uri(ApiRoutes.ComputerApprove(agent.ComputerId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        await agent.StepAsync();
        await agent.StepAsync();

        // First report: the baseline, no alerts for software that was already there.
        Assert.Empty(await EventsAsync(admin, agent.ComputerId, SecurityEventType.SoftwareInstalled));
        var titles = await admin.GetFromJsonAsync<List<SoftwareTitleSummary>>(ApiRoutes.SoftwareInventory);
        Assert.Equal(2, titles!.Count);
        Assert.True(titles.Single(t => t.Name.StartsWith("Microsoft Office", StringComparison.Ordinal)).IsApproved);
        Assert.False(titles.Single(t => t.Name == "Old Tool").IsApproved);
        Assert.Equal(1, (await admin.GetFromJsonAsync<DashboardOverviewResponse>(ApiRoutes.DashboardOverview))!.ComputersWithUnapprovedSoftware);

        // Something new appears, something is removed.
        agent.Inventory.Software.RemoveAll(s => s.Name == "Old Tool");
        agent.Inventory.Software.Add(new InstalledSoftware("Free Game", "2.0", "Games Ltd", null, "User"));
        server.Clock.Advance(TimeSpan.FromMinutes(16));
        await agent.StepAsync();

        var installed = Assert.Single(await EventsAsync(admin, agent.ComputerId, SecurityEventType.SoftwareInstalled));
        Assert.Equal(EventSeverities.Warning, installed.Severity);
        Assert.Contains("Free Game", installed.Details, StringComparison.Ordinal);
        Assert.Contains("Old Tool", Assert.Single(await EventsAsync(admin, agent.ComputerId, SecurityEventType.SoftwareRemoved)).Details, StringComparison.Ordinal);

        var unapproved = await admin.GetFromJsonAsync<List<SoftwareTitleSummary>>($"{ApiRoutes.SoftwareInventory}?unapprovedOnly=true");
        Assert.Equal("Free Game", Assert.Single(unapproved!).Name);
        var onComputer = await admin.GetFromJsonAsync<List<InstalledSoftwareResponse>>($"{ApiRoutes.SoftwareInventoryComputers}?computerId={agent.ComputerId}");
        Assert.Equal(["Free Game", "Microsoft Office Professional Plus 2021"], onComputer!.Select(s => s.Name));
        Assert.Equal("User", onComputer![0].Scope);
    }

    [Fact]
    public async Task Staff_and_auditors_cannot_manage_software()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        var title = await ApproveTitleAsync(admin);
        var (_, staffToken) = await server.CreateActiveStaffAsync(owner, "EMP802", "Staff member pass 2026");
        var (auditorToken, _) = await server.CreateAdminAsync(owner, "auditor2", AdminRoles.Auditor);
        using var staff = server.Client(staffToken);
        using var auditor = server.Client(auditorToken);

        foreach (var client in new[] { staff, auditor })
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync(ApiRoutes.ApprovedSoftware, new SaveApprovedSoftwareRequest("X Tool", null, null))).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await UploadAsync(client, title.Id)).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync(ApiRoutes.SoftwareDeployments, new CreateDeploymentRequest(Guid.NewGuid(), [Guid.NewGuid()]))).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync(ApiRoutes.SoftwareRequestApprove(Guid.NewGuid()), new ApproveSoftwareRequest(Guid.NewGuid(), null, null))).StatusCode);
        }

        // Staff cannot read other people's requests or the inventory; auditors can read.
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri(ApiRoutes.SoftwareRequests, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await staff.GetAsync(new Uri(ApiRoutes.SoftwareInventory, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(new Uri(ApiRoutes.SoftwareRequests, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(new Uri(ApiRoutes.SoftwareInventory, UriKind.Relative))).StatusCode);

        // Administrators do not have a staff request list of their own, and cannot use the agent endpoints.
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PostAsJsonAsync(ApiRoutes.SoftwareRequests, new CreateSoftwareRequest("X Tool", "Because I want it"))).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await admin.GetAsync(new Uri(ApiRoutes.AgentJobs, UriKind.Relative))).StatusCode);
    }
}
