using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Contracts;

namespace OfficeSecurity.Client.Core;

public sealed record PairingResult(bool Success, ClientSettings? Settings, string? Error);

/// <summary>
/// Connects a client to the office server for the first time. The server's CA certificate is
/// downloaded and accepted only if it matches the pairing code shown on the server; afterwards the
/// server's HTTPS certificate must chain to that CA.
/// </summary>
public static class PairingService
{
    public static async Task<PairingResult> PairAsync(string serverAddress, string pairingCode, CancellationToken cancellationToken = default)
    {
        if (!ClientSettings.TryParseServerAddress(serverAddress, out var address))
        {
            return new PairingResult(false, null, "Enter the server address, for example office-pc or 192.168.1.20.");
        }

        if (PairingCode.Normalize(pairingCode).Length != 20)
        {
            return new PairingResult(false, null, "Enter the 20-character pairing code shown on the server (for example 6162-C295-C5AF-BC9A-60DD).");
        }

        byte[] caDer;
        X509Certificate2? presented = null;
        var presentedErrors = SslPolicyErrors.None;
        try
        {
            // The CA is not trusted yet, so the certificate the server presents is recorded rather than
            // validated here. Nothing is trusted until the downloaded CA matches the pairing code and the
            // recorded certificate chains to that CA (checked below).
            using var untrusted = new HttpClient(new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    {
                        presented ??= certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                        presentedErrors = errors;
                        return presented is not null;
                    },
                },
                UseProxy = false,
            })
            { BaseAddress = address, Timeout = TimeSpan.FromSeconds(15) };
            caDer = await untrusted.GetByteArrayAsync(new Uri(ApiRoutes.CaCertificate, UriKind.Relative), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new PairingResult(false, null, $"Could not reach the server at {address}. Check the address, that the server is running, and that Windows Firewall allows port {address!.Port}.");
        }

        if (!PairingCode.Matches(caDer, pairingCode))
        {
            return new PairingResult(false, null, "The pairing code does not match this server. Check the code shown on the server. If it is correct, you may not be connected to the real office server.");
        }

        using var ca = X509CertificateLoader.LoadCertificate(caDer);
        using (presented)
        {
            if (!ServerTrust.Validate(ca, presented, presentedErrors))
            {
                return new PairingResult(false, null, "The server's security certificate is not valid for this address. Try another address from the server's connection information.");
            }
        }

        using var trusted = new ApiClient(address!, ca);
        var health = await trusted.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
        if (!health.IsReachable)
        {
            return new PairingResult(false, null, "The server's security certificate could not be verified for this address. Try another address from the server's connection information. " + health.Error);
        }

        return new PairingResult(true, new ClientSettings { ServerAddress = address!.ToString().TrimEnd('/'), CaCertificateBase64 = Convert.ToBase64String(caDer) }, null);
    }
}
