namespace OfficeSecurity.Server.Application.Security;

/// <summary>
/// Password rules following NIST SP 800-63B: a minimum length and a block-list rather than forced
/// character-class composition.
/// </summary>
public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "password12345", "password123456", "passwordpassword", "123456789012", "1234567890123",
        "qwertyuiop12", "qwertyuiopasdf", "iloveyou1234", "welcome12345", "letmein12345", "admin1234567",
        "administrator", "changeme1234", "abcdefghijkl", "111111111111", "000000000000", "aaaaaaaaaaaa",
        "officesecurity", "company12345", "p@ssw0rd1234", "passw0rd1234",
    };

    /// <returns>An error message, or <c>null</c> when the password is acceptable.</returns>
    public static string? Validate(string? password, string loginName)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinLength)
        {
            return $"Password must be at least {MinLength} characters long.";
        }

        if (password.Length > MaxLength)
        {
            return $"Password must be at most {MaxLength} characters long.";
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            return "Password cannot be only spaces.";
        }

        if (password.Distinct().Count() < 4)
        {
            return "Password is too repetitive.";
        }

        if (CommonPasswords.Contains(password))
        {
            return "This password is too common. Choose a different one.";
        }

        if (!string.IsNullOrWhiteSpace(loginName) && password.Contains(loginName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return "Password must not contain your user name or employee code.";
        }

        return null;
    }
}
