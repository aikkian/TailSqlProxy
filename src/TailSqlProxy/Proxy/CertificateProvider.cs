using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Proxy;

public class CertificateProvider
{
    private readonly ProxyOptions _options;
    private readonly ILogger<CertificateProvider> _logger;
    private X509Certificate2? _certificate;

    public CertificateProvider(IOptions<ProxyOptions> options, ILogger<CertificateProvider> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public X509Certificate2 GetCertificate()
    {
        if (_certificate != null)
            return _certificate;

        var certOptions = _options.Certificate;

        if (!string.IsNullOrWhiteSpace(certOptions.Path))
        {
            _logger.LogInformation("Loading certificate from {Path}", certOptions.Path);
            _certificate = new X509Certificate2(certOptions.Path, certOptions.Password);
        }
        else if (certOptions.AutoGenerate)
        {
            _logger.LogInformation("Auto-generating self-signed certificate for TDS proxy");
            _certificate = GenerateSelfSignedCertificate();
        }
        else
        {
            throw new InvalidOperationException(
                "No certificate configured. Set Certificate.Path or Certificate.AutoGenerate=true in appsettings.json.");
        }

        return _certificate;
    }

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
