using System.Security.Cryptography;

namespace OfficeSecurity.Contracts;

/// <summary>
/// Short fingerprint of the server's certificate authority, shown on the server and typed into
/// clients when they are first connected. It lets a client verify it is talking to the real office
/// server before trusting it (80 bits of the SHA-256 fingerprint).
/// </summary>
public static class PairingCode
{
    private const int Characters = 20;

    public static string Compute(ReadOnlySpan<byte> caCertificateDer)
    {
        var hex = Convert.ToHexString(SHA256.HashData(caCertificateDer))[..Characters];
        return string.Join('-', Enumerable.Range(0, Characters / 4).Select(i => hex.Substring(i * 4, 4)));
    }

    public static string Normalize(string? code) =>
        new((code ?? string.Empty).Where(char.IsAsciiHexDigit).Select(char.ToUpperInvariant).ToArray());

    public static bool Matches(ReadOnlySpan<byte> caCertificateDer, string? typedCode)
    {
        var expected = Normalize(Compute(caCertificateDer));
        var typed = Normalize(typedCode);
        return typed.Length == Characters &&
               CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(expected), System.Text.Encoding.ASCII.GetBytes(typed));
    }
}
