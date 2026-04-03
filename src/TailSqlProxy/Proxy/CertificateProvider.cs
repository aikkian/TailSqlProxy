using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Proxy;

public class CertificateProvider
{
    private readonly Lazy<X509Certificate2> _certificate;

    public CertificateProvider(IOptions<ProxyOptions> options, ILogger<CertificateProvider> logger)
    {
        var proxyOptions = options.Value;
        _certificate = new Lazy<X509Certificate2>(() =>
        {
            var certOptions = proxyOptions.Certificate;

            if (!string.IsNullOrWhiteSpace(certOptions.Path))
            {
                logger.LogInformation("Loading certificate from {Path}", certOptions.Path);
                return new X509Certificate2(certOptions.Path, certOptions.Password);
            }

            if (certOptions.AutoGenerate)
            {
                logger.LogInformation("Auto-generating self-signed certificate for TDS proxy");
                return GenerateSelfSignedCertificate();
            }

            throw new InvalidOperationException(
                "No certificate configured. Set Certificate.Path or Certificate.AutoGenerate=true in appsettings.json.");
        }, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public X509Certificate2 GetCertificate() => _certificate.Value;

    private X509Certificate2 GenerateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=TailSqlProxy, O=TailSqlProxy Self-Signed",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, // Server Authentication
                critical: false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddDnsName(Environment.MachineName);
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());

        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        // On Linux, export and re-import to ensure the private key is accessible
        var exported = cert.Export(X509ContentType.Pfx, "");
        return new X509Certificate2(exported, "", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }
}
