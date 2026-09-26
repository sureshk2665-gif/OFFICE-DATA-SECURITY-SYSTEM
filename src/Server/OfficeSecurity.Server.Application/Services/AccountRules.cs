using System.Text.RegularExpressions;

namespace OfficeSecurity.Server.Application.Services;

/// <summary>Input rules for account fields.</summary>
public static partial class AccountRules
{
    public const int MaxDisplayNameLength = 100;
    public const int MaxDepartmentLength = 100;

    public static string Normalize(string value) => value.Trim().ToUpperInvariant();

    public static string? ValidateUsername(string? username) =>
        username is not null && UsernameRegex().IsMatch(username.Trim())
            ? null
            : "User name must be 3–64 characters: letters, digits, dot, dash or underscore.";

    public static string? ValidateEmployeeCode(string? code) =>
        code is not null && EmployeeCodeRegex().IsMatch(code.Trim())
            ? null
            : "Employee code must be 2–32 characters: letters, digits, dash or underscore.";

    public static string? ValidateDisplayName(string? name) =>
        string.IsNullOrWhiteSpace(name) || name.Trim().Length > MaxDisplayNameLength || name.Any(char.IsControl)
            ? $"Name is required and must be at most {MaxDisplayNameLength} characters."
            : null;

    public static string? ValidateDepartment(string? department) =>
        department is not null && (department.Trim().Length > MaxDepartmentLength || department.Any(char.IsControl))
            ? $"Department must be at most {MaxDepartmentLength} characters."
            : null;

    public static string? CleanOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    [GeneratedRegex("^[A-Za-z0-9._-]{3,64}$")]
    private static partial Regex UsernameRegex();

    [GeneratedRegex("^[A-Za-z0-9_-]{2,32}$")]
    private static partial Regex EmployeeCodeRegex();
}
