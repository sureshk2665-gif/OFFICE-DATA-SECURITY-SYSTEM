using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OfficeSecurity.Server.Application.Abstractions;

namespace OfficeSecurity.Server.Infrastructure.Certificates;

/// <summary>Certificates the server uses: its private CA and the HTTPS certificate issued by it.</summary>
public sealed record ServerCertificates(X509Certificate2 CaCertificate, byte[] ServerCertificatePfx, IReadOnlyList<string> ServerNames);

/// <summary>
/// Private certificate authority created on first start (ADR-0003). Private keys are stored only in
/// encrypted form (<see cref="ISecretProtector"/>). The HTTPS certificate is re-issued automatically when it
/// nears expiry or when the server's host name or IP addresses change.
/// </summary>
public sealed class ServerCertificateAuthority(string certificateDirectory, ISecretProtector protector, TimeProvider clock)
{
    private const string CaFile = "ca.pfx.protected";
    private const string ServerFile = "server-tls.pfx.protected";
    private const string PublicCaFile = "office-security-ca.cer";
    private static readonly TimeSpan CaLifetime = TimeSpan.FromDays(3650);
    private static readonly TimeSpan ServerLifetime = TimeSpan.FromDays(397);
    private static readonly TimeSpan RenewBefore = TimeSpan.FromDays(30);

    public ServerCertificates LoadOrCreate(IReadOnlyCollection<string>? additionalNames = null)
    {
        Directory.CreateDirectory(certificateDirectory);
        var now = clock.GetUtcNow();

        using var ca = LoadPfx(CaFile) ?? CreateCa(now);
        var names = CollectServerNames(additionalNames);

        var serverPfx = LoadProtected(ServerFile);
        if (serverPfx is null || NeedsNewServerCertificate(serverPfx, ca, names, now))
        {
            serverPfx = IssueServerCertificate(ca, names, now);
            SaveProtected(ServerFile, serverPfx);
        }

        var caPublic = X509CertificateLoader.LoadCertificate(ca.RawData);
        File.WriteAllBytes(Path.Combine(certificateDirectory, PublicCaFile), caPublic.RawData);
        return new ServerCertificates(caPublic, serverPfx, names);
    }

    /// <summary>Host names and addresses the HTTPS certificate is valid for.</summary>
    public static IReadOnlyList<string> CollectServerNames(IReadOnlyCollection<string>? additionalNames = null)
    {
        var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase) { "localhost", "127.0.0.1", "::1", Environment.MachineName };

        var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
        if (!string.IsNullOrWhiteSpace(domain))
        {
            names.Add($"{Environment.MachineName}.{domain}");
        }

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up))
        {
            foreach (var address in nic.GetIPProperties().UnicastAddresses.Select(a => a.Address))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address))
                {
                    names.Add(address.ToString());
                }
            }
        }

        foreach (var extra in additionalNames ?? [])
        {
            if (!string.IsNullOrWhiteSpace(extra))
            {
                names.Add(extra.Trim());
            }
        }

        return [.. names];
    }

    private X509Certificate2 CreateCa(DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            $"CN=Office Security Local CA {now:yyyyMMdd}, O=Office Computer Security System", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var ca = request.CreateSelfSigned(now.AddMinutes(-5), now + CaLifetime);
        SaveProtected(CaFile, ca.Export(X509ContentType.Pkcs12));
        return ca;
    }

    private static byte[] IssueServerCertificate(X509Certificate2 ca, IReadOnlyList<string> names, DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={Environment.MachineName}, O=Office Computer Security System", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication")], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in names)
        {
            if (IPAddress.TryParse(name, out var ip))
            {
                san.AddIpAddress(ip);
            }
            else
            {
                san.AddDnsName(name);
            }
        }

        request.CertificateExtensions.Add(san.Build());

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        var notAfter = now + ServerLifetime;
        if (notAfter > ca.NotAfter)
        {
            notAfter = ca.NotAfter;
        }

        using var issued = request.Create(ca, now.AddMinutes(-5), notAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(key);
        return withKey.Export(X509ContentType.Pkcs12);
    }

    private static bool NeedsNewServerCertificate(byte[] pfx, X509Certificate2 ca, IReadOnlyList<string> names, DateTimeOffset now)
    {
        using var cert = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.EphemeralKeySet);
        if (cert.NotAfter.ToUniversalTime() - now.UtcDateTime < RenewBefore || !string.Equals(cert.Issuer, ca.Subject, StringComparison.Ordinal))
        {
            return true;
        }

        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san is null)
        {
            return true;
        }

        var covered = new HashSet<string>(san.EnumerateDnsNames(), StringComparer.OrdinalIgnoreCase);
        covered.UnionWith(san.EnumerateIPAddresses().Select(a => a.ToString()));
        return !names.All(covered.Contains);
    }

    private X509Certificate2? LoadPfx(string fileName)
    {
        var bytes = LoadProtected(fileName);
        return bytes is null ? null : X509CertificateLoader.LoadPkcs12(bytes, null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }

    private byte[]? LoadProtected(string fileName)
    {
        var path = Path.Combine(certificateDirectory, fileName);
        return File.Exists(path) ? protector.Unprotect(File.ReadAllBytes(path)) : null;
    }

    private void SaveProtected(string fileName, byte[] data)
    {
        var path = Path.Combine(certificateDirectory, fileName);
        var temp = path + ".tmp";
        File.WriteAllBytes(temp, protector.Protect(data));
        File.Move(temp, path, overwrite: true);
    }
}
