using System.Security.Cryptography;
using System.Text;

namespace OfficeSecurity.Server.Application.Security;

/// <summary>Generation and hashing of one-time setup codes, session tokens and tickets.</summary>
public static class SecretCodes
{
    // No 0/O, 1/I/L: codes are read aloud or typed by non-technical users.
    private const string SetupCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private const int SetupCodeLength = 12;

    /// <summary>Human-typeable code such as <c>K7QM-2XRP-9FTA</c> (about 59 bits of entropy).</summary>
    public static string NewSetupCode()
    {
        var chars = new char[SetupCodeLength];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = SetupCodeAlphabet[RandomNumberGenerator.GetInt32(SetupCodeAlphabet.Length)];
        }

        var raw = new string(chars);
        return $"{raw[..4]}-{raw[4..8]}-{raw[8..]}";
    }

    /// <summary>Removes separators and case so "k7qm 2xrp-9fta" matches "K7QM-2XRP-9FTA".</summary>
    public static string NormalizeSetupCode(string? code) =>
        new((code ?? string.Empty).Where(char.IsAsciiLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    /// <summary>256-bit random bearer token, URL-safe.</summary>
    public static string NewToken() => Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    /// <summary>SHA-256 (hex) used to store codes and tokens; they are high-entropy, so no salt is needed.</summary>
    public static string HashForStorage(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
