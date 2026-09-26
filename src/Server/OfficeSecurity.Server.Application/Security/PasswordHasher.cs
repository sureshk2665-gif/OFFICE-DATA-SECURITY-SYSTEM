using System.Globalization;
using System.Security.Cryptography;

namespace OfficeSecurity.Server.Application.Security;

/// <summary>
/// PBKDF2-HMAC-SHA512 password hashing (OWASP recommendation: at least 210,000 iterations).
/// Stored format: <c>pbkdf2-sha512$iterations$saltBase64$hashBase64</c>.
/// </summary>
public sealed class PasswordHasher(int iterations = PasswordHasher.DefaultIterations)
{
    public const int DefaultIterations = 210_000;
    private const string Scheme = "pbkdf2-sha512";
    private const int SaltSize = 16;
    private const int HashSize = 32;

    // Used to spend comparable time when the account does not exist (reduces user enumeration by timing).
    private readonly Lazy<string> _dummyHash = new(() => HashCore("not-a-real-password", iterations));

    public int Iterations { get; } = iterations > 0 ? iterations : throw new ArgumentOutOfRangeException(nameof(iterations));

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return HashCore(password, Iterations);
    }

    public bool Verify(string password, string? storedHash)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (string.IsNullOrEmpty(storedHash))
        {
            VerifyCore(password, _dummyHash.Value);
            return false;
        }

        return VerifyCore(password, storedHash);
    }

    public bool NeedsRehash(string storedHash) =>
        !TryParse(storedHash, out var storedIterations, out _, out _) || storedIterations < Iterations;

    private static string HashCore(string password, int iterations)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, HashSize);
        return string.Create(CultureInfo.InvariantCulture, $"{Scheme}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    private static bool VerifyCore(string password, string storedHash)
    {
        if (!TryParse(storedHash, out var iterations, out var salt, out var expected))
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static bool TryParse(string storedHash, out int iterations, out byte[] salt, out byte[] hash)
    {
        iterations = 0;
        salt = [];
        hash = [];
        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != Scheme ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations) || iterations <= 0)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
            return salt.Length > 0 && hash.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
