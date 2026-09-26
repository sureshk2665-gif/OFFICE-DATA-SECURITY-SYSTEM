using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace OfficeSecurity.Server.Application.Security;

/// <summary>
/// RFC 6238 time-based one-time passwords (HMAC-SHA1, 30-second steps, 6 digits): the format
/// supported by Microsoft Authenticator, Google Authenticator and similar apps.
/// </summary>
public static class Totp
{
    public const int SecretSize = 20;
    public const int Digits = 6;
    public const int StepSeconds = 30;

    /// <summary>Accepted clock drift in steps either side of the current step.</summary>
    public const int AllowedDriftSteps = 1;

    public static byte[] GenerateSecret() => RandomNumberGenerator.GetBytes(SecretSize);

    public static long GetTimeStep(DateTimeOffset time) => time.ToUnixTimeSeconds() / StepSeconds;

    public static string ComputeCode(ReadOnlySpan<byte> secret, long timeStep)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, timeStep);
        Span<byte> hash = stackalloc byte[20];
        // RFC 6238 default and the only algorithm all common authenticator apps support. HMAC-SHA1 remains
        // secure as a MAC; SHA-1 collision attacks do not apply to HMAC.
#pragma warning disable CA5350
        HMACSHA1.HashData(secret, counter, hash);
#pragma warning restore CA5350

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        var code = binary % 1_000_000;
        return code.ToString("D6", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Verifies a code. Returns the matched time step, or <c>null</c>. Codes for steps at or before
    /// <paramref name="lastUsedTimeStep"/> are rejected so a code cannot be reused.
    /// </summary>
    public static long? Verify(ReadOnlySpan<byte> secret, string? code, DateTimeOffset now, long lastUsedTimeStep)
    {
        var normalized = code?.Replace(" ", string.Empty, StringComparison.Ordinal).Trim();
        if (normalized is null || normalized.Length != Digits || !normalized.All(char.IsAsciiDigit))
        {
            return null;
        }

        var current = GetTimeStep(now);
        long? matched = null;
        for (var step = current - AllowedDriftSteps; step <= current + AllowedDriftSteps; step++)
        {
            // Evaluate every candidate so timing does not reveal which step matched.
            var candidate = ComputeCode(secret, step);
            if (CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(candidate), System.Text.Encoding.ASCII.GetBytes(normalized)) && step > lastUsedTimeStep)
            {
                matched = step;
            }
        }

        return matched;
    }

    public static string BuildOtpAuthUri(string issuer, string accountName, string secretBase32) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}" +
        $"?secret={secretBase32}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
}
