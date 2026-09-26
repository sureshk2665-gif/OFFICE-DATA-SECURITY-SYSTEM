using System.Net;
using System.Net.Http.Json;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Server.IntegrationTests;

public sealed class StaffAccountTests
{
    private const string StaffPassword = "Staff member pass 2026";

    [Fact]
    public async Task Admin_creates_staff_who_activates_with_setup_code_and_signs_in()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        using var anonymous = server.Client();

        var code = await (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP001", "Priya Raman", "Accounts")))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SetupCodeResponse>();

        var beforeActivation = await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP001", StaffPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, beforeActivation.StatusCode);

        var wrongCode = await anonymous.PostAsJsonAsync(ApiRoutes.StaffActivate, new StaffActivateRequest("EMP001", "AAAA-BBBB-CCCC", StaffPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCode.StatusCode);

        var weakPassword = await anonymous.PostAsJsonAsync(ApiRoutes.StaffActivate, new StaffActivateRequest("EMP001", code!.SetupCode, "emp001emp001"));
        Assert.Equal(HttpStatusCode.BadRequest, weakPassword.StatusCode);

        var activated = await anonymous.PostAsJsonAsync(ApiRoutes.StaffActivate,
            new StaffActivateRequest("emp001", code.SetupCode.ToLowerInvariant(), StaffPassword));
        Assert.Equal(HttpStatusCode.OK, activated.StatusCode);

        var reuse = await anonymous.PostAsJsonAsync(ApiRoutes.StaffActivate, new StaffActivateRequest("EMP001", code.SetupCode, "Another password 2026"));
        Assert.Equal(HttpStatusCode.Unauthorized, reuse.StatusCode);

        var session = await (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP001", StaffPassword)))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SessionResponse>();
        Assert.Equal(AccountTypes.Staff, session!.User.AccountType);
        Assert.Equal("Priya Raman", session.User.DisplayName);
    }

    [Fact]
    public async Task Duplicate_employee_code_is_rejected()
    {
        await using var server = new ServerFactory();
        using var admin = server.Client(await server.OwnerTokenAsync());

        (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("EMP002", "A", null))).EnsureSuccessStatusCode();
        var duplicate = await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest("emp002", "B", null));

        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
    }

    [Fact]
    public async Task Disabling_staff_ends_their_session_and_blocks_sign_in_until_enabled()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var (staffId, staffToken) = await server.CreateActiveStaffAsync(owner, "EMP003", StaffPassword);
        using var admin = server.Client(owner);
        using var staff = server.Client(staffToken);
        using var anonymous = server.Client();

        (await admin.PostAsync(new Uri(ApiRoutes.StaffDisable(staffId), UriKind.Relative), null)).EnsureSuccessStatusCode();

        Assert.Equal(HttpStatusCode.Unauthorized, (await staff.GetAsync(new Uri(ApiRoutes.Me, UriKind.Relative))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP003", StaffPassword))).StatusCode);

        (await admin.PostAsync(new Uri(ApiRoutes.StaffEnable(staffId), UriKind.Relative), null)).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.OK,
            (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP003", StaffPassword))).StatusCode);
    }

    [Fact]
    public async Task Reset_clears_old_password_and_issues_new_code()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        var (staffId, _) = await server.CreateActiveStaffAsync(owner, "EMP004", StaffPassword);
        using var admin = server.Client(owner);
        using var anonymous = server.Client();

        var code = await (await admin.PostAsync(new Uri(ApiRoutes.StaffResetSetupCode(staffId), UriKind.Relative), null))
            .EnsureSuccessStatusCode().Content.ReadFromJsonAsync<SetupCodeResponse>();

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.PostAsJsonAsync(ApiRoutes.StaffLogin, new StaffLoginRequest("EMP004", StaffPassword))).StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await anonymous.PostAsJsonAsync(ApiRoutes.StaffActivate, new StaffActivateRequest("EMP004", code!.SetupCode, "Fresh staff password 1"))).StatusCode);
    }

    [Fact]
    public async Task Staff_list_supports_search_status_filter_and_paging()
    {
        await using var server = new ServerFactory();
        var owner = await server.OwnerTokenAsync();
        using var admin = server.Client(owner);
        for (var i = 1; i <= 5; i++)
        {
            (await admin.PostAsJsonAsync(ApiRoutes.Staff, new CreateStaffRequest($"S{i:00}", $"Person {i}", i % 2 == 0 ? "Sales" : "Accounts"))).EnsureSuccessStatusCode();
        }

        await server.CreateActiveStaffAsync(owner, "S99", StaffPassword);

        var page = await admin.GetFromJsonAsync<PagedResult<StaffSummary>>($"{ApiRoutes.Staff}?page=2&pageSize=2");
        Assert.Equal(6, page!.TotalCount);
        Assert.Equal(2, page.Items.Count);

        var sales = await admin.GetFromJsonAsync<PagedResult<StaffSummary>>($"{ApiRoutes.Staff}?search=sales");
        Assert.Equal(2, sales!.TotalCount);

        var active = await admin.GetFromJsonAsync<PagedResult<StaffSummary>>($"{ApiRoutes.Staff}?status=Active");
        Assert.Equal("S99", Assert.Single(active!.Items).EmployeeCode);

        var overview = await admin.GetFromJsonAsync<DashboardOverviewResponse>(ApiRoutes.DashboardOverview);
        Assert.Equal(6, overview!.StaffTotal);
        Assert.Equal(1, overview.StaffActive);
        Assert.Equal(5, overview.StaffPendingActivation);
    }
}
