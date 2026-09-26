using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace OfficeSecurity.Server.IntegrationTests;

/// <summary>
/// Test-only: the in-memory test server has no TLS, so tests pass the agent's client certificate in a
/// header. Registered only by <see cref="ServerFactory"/>; the real server never reads this header.
/// Real mutual TLS is covered by the Kestrel-based tests.
/// </summary>
internal sealed class TestClientCertificateFilter : IStartupFilter
{
    public const string Header = "X-Test-Client-Certificate";

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            if (context.Request.Headers.TryGetValue(Header, out var value) && context.Connection.ClientCertificate is null)
            {
                context.Connection.ClientCertificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(value.ToString()));
            }

            await nextMiddleware();
        });
        next(app);
    };
}

/// <summary>Adds the test client-certificate header to every request.</summary>
internal sealed class CertificateHeaderHandler(X509Certificate2 certificate) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Headers.Add(TestClientCertificateFilter.Header, Convert.ToBase64String(certificate.RawData));
        return base.SendAsync(request, cancellationToken);
    }
}
