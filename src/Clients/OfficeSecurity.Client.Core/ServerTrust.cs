using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace OfficeSecurity.Client.Core;

/// <summary>
/// TLS validation pinned to the office server's own certificate authority. Certificates from any
/// other authority (including publicly trusted ones) are rejected, and the host name must match.
/// </summary>
public static class ServerTrust
{
    public static bool Validate(X509Certificate2 pinnedCa, X509Certificate? serverCertificate, SslPolicyErrors errors)
    {
        ArgumentNullException.ThrowIfNull(pinnedCa);
        if (serverCertificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) ||
            errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            return false;
        }

        using var leaf = X509CertificateLoader.LoadCertificate(serverCertificate.GetRawCertData());
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(pinnedCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        if (!chain.Build(leaf))
        {
            return false;
        }

        // The chain must end at exactly the pinned CA.
        var root = chain.ChainElements[^1].Certificate;
        return root.RawData.AsSpan().SequenceEqual(pinnedCa.RawData);
    }

    public static HttpMessageHandler CreatePinnedHandler(X509Certificate2 pinnedCa) =>
        new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) => Validate(pinnedCa, certificate, errors),
            },
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            UseProxy = false,
        };
}
