namespace OfficeSecurity.Contracts;

/// <summary>Versioned API route constants shared by the server and all clients.</summary>
public static class ApiRoutes
{
    public const string Prefix = "/api/v1";
    public const string Health = Prefix + "/health";

    /// <summary>Public CA certificate (DER), used by clients during pairing.</summary>
    public const string CaCertificate = Prefix + "/pairing/ca-certificate";

    public const string SetupStatus = Prefix + "/setup/status";
    public const string SetupFirstAdmin = Prefix + "/setup/first-admin";

    public const string AdminLogin = Prefix + "/auth/admin/login";
    public const string AdminMfa = Prefix + "/auth/admin/mfa";
    public const string AdminActivate = Prefix + "/auth/admin/activate";
    public const string AdminConfirmMfa = Prefix + "/auth/admin/confirm-mfa";
    public const string StaffLogin = Prefix + "/auth/staff/login";
    public const string StaffActivate = Prefix + "/auth/staff/activate";
    public const string Me = Prefix + "/auth/me";
    public const string Logout = Prefix + "/auth/logout";
    public const string ChangePassword = Prefix + "/auth/change-password";

    public const string Staff = Prefix + "/staff";
    public const string Admins = Prefix + "/admins";
    public const string Audit = Prefix + "/audit";
    public const string AuditVerify = Prefix + "/audit/verify";
    public const string DashboardOverview = Prefix + "/dashboard/overview";

    public const string Computers = Prefix + "/computers";
    public const string EnrollmentCodes = Computers + "/enrollment-codes";
    public const string Policies = Prefix + "/policies";
    public const string Events = Prefix + "/events";

    public const string AgentEnroll = Prefix + "/agent/enroll";
    public const string AgentEnrollStatus = Prefix + "/agent/enroll/status";
    public const string AgentHeartbeat = Prefix + "/agent/heartbeat";
    public const string AgentPolicy = Prefix + "/agent/policy";
    public const string AgentEvents = Prefix + "/agent/events";
    public const string AgentInventory = Prefix + "/agent/inventory";
    public const string AgentLoginTicket = Prefix + "/agent/login-ticket";
    public const string AgentJobs = Prefix + "/agent/jobs";

    public const string SoftwareRequests = Prefix + "/software-requests";
    public const string MySoftwareRequests = SoftwareRequests + "/mine";
    public const string ApprovedSoftware = Prefix + "/software/approved";
    public const string SoftwarePackages = Prefix + "/software/packages";
    public const string SoftwareDeployments = Prefix + "/software/deployments";
    public const string SoftwareInventory = Prefix + "/software/inventory";
    public const string SoftwareInventoryComputers = SoftwareInventory + "/computers";

    public static string ComputerExemptions(Guid id) => $"{Computers}/{id}/exemptions";
    public static string ComputerExemptionById(Guid id, Guid exemptionId) => $"{Computers}/{id}/exemptions/{exemptionId}";
    public static string AgentJobStart(Guid id) => $"{AgentJobs}/{id}/start";
    public static string AgentJobPackage(Guid id) => $"{AgentJobs}/{id}/package";
    public static string AgentJobResult(Guid id) => $"{AgentJobs}/{id}/result";
    public static string SoftwareRequestApprove(Guid id) => $"{SoftwareRequests}/{id}/approve";
    public static string SoftwareRequestReject(Guid id) => $"{SoftwareRequests}/{id}/reject";
    public static string ApprovedSoftwareById(Guid id) => $"{ApprovedSoftware}/{id}";
    public static string ApprovedSoftwarePackages(Guid id) => $"{ApprovedSoftware}/{id}/packages";
    public static string SoftwarePackageById(Guid id) => $"{SoftwarePackages}/{id}";
    public static string DeploymentCancel(Guid id) => $"{SoftwareDeployments}/{id}/cancel";

    public static string ComputerById(Guid id) => $"{Computers}/{id}";
    public static string ComputerApprove(Guid id) => $"{Computers}/{id}/approve";
    public static string ComputerReject(Guid id) => $"{Computers}/{id}/reject";
    public static string ComputerRetire(Guid id) => $"{Computers}/{id}/retire";
    public static string ComputerPolicy(Guid id) => $"{Computers}/{id}/policy";
    public static string ComputerStaff(Guid id) => $"{Computers}/{id}/staff";
    public static string PolicyById(Guid id) => $"{Policies}/{id}";

    public static string StaffById(Guid id) => $"{Staff}/{id}";
    public static string StaffDisable(Guid id) => $"{Staff}/{id}/disable";
    public static string StaffEnable(Guid id) => $"{Staff}/{id}/enable";
    public static string StaffResetSetupCode(Guid id) => $"{Staff}/{id}/reset";
    public static string AdminDisable(Guid id) => $"{Admins}/{id}/disable";
    public static string AdminEnable(Guid id) => $"{Admins}/{id}/enable";
    public static string AdminResetSetupCode(Guid id) => $"{Admins}/{id}/reset";
}
