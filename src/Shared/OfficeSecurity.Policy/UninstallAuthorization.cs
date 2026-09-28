using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace OfficeSecurity.Policy;

/// <summary>
/// An administrator's permission to remove the agent from one computer, valid for a limited time. The server
/// signs it with the policy signing key, so the agent can check it without contacting the server (the computer
/// may be offline or about to be retired).
/// </summary>
public static class UninstallAuthorization
{
    public const string Prefix = "U1-";
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);

    /// <summary>What is signed: the purpose, the computer and the expiry.</summary>
    public static byte[] Payload(Guid computerId, DateTimeOffset expiresAtUtc) =>
        Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture, $"ocss-uninstall-v1|{computerId:N}|{expiresAtUtc.ToUnixTimeSeconds()}"));

    /// <summary>The code an administrator types or pastes: expiry (8 bytes) + ECDSA P-256 signature (64 bytes), base64url.</summary>
    public static string Encode(DateTimeOffset expiresAtUtc, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        var bytes = new byte[8 + signature.Length];
        BinaryPrimitives.WriteInt64BigEndian(bytes, expiresAtUtc.ToUnixTimeSeconds());
        signature.CopyTo(bytes, 8);
        return Prefix + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Checks a code for this computer. Returns null when valid, otherwise the reason in plain language.</summary>
    public static string? Verify(string? code, Guid computerId, byte[] trustedSubjectPublicKeyInfo, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trustedSubjectPublicKeyInfo);
        var text = (code ?? string.Empty).Trim();
        if (!text.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return "This is not an uninstall code. Get one in the dashboard: Computers → select the computer → Uninstall code.";
        }

        byte[] bytes;
        try
        {
            var body = text[Prefix.Length..].Replace('-', '+').Replace('_', '/');
            bytes = Convert.FromBase64String(body.PadRight(body.Length + ((4 - (body.Length % 4)) % 4), '='));
        }
        catch (FormatException)
        {
            return "The uninstall code is not complete. Copy it again from the dashboard.";
        }

        if (bytes.Length != 8 + 64)
        {
            return "The uninstall code is not complete. Copy it again from the dashboard.";
        }

        var expires = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64BigEndian(bytes));
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(trustedSubjectPublicKeyInfo, out _);
        if (!key.VerifyData(Payload(computerId, expires), bytes.AsSpan(8), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            return "This uninstall code is not valid for this computer.";
        }

        return expires <= nowUtc ? "This uninstall code has expired. Get a new one in the dashboard." : null;
    }
}
