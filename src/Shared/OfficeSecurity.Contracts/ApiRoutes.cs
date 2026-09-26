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

    public static string StaffById(Guid id) => $"{Staff}/{id}";
    public static string StaffDisable(Guid id) => $"{Staff}/{id}/disable";
    public static string StaffEnable(Guid id) => $"{Staff}/{id}/enable";
    public static string StaffResetSetupCode(Guid id) => $"{Staff}/{id}/reset";
    public static string AdminDisable(Guid id) => $"{Admins}/{id}/disable";
    public static string AdminEnable(Guid id) => $"{Admins}/{id}/enable";
    public static string AdminResetSetupCode(Guid id) => $"{Admins}/{id}/reset";
}
