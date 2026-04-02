namespace TailSqlProxy.Configuration;

public class ProxyOptions
{
    public int ListenPort { get; set; } = 1433;
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int MaxConcurrentConnections { get; set; } = 100;
    public CertificateOptions Certificate { get; set; } = new();
    public string AuditLogPath { get; set; } = "logs/audit-.log";
}

public class CertificateOptions
{
    public string? Path { get; set; }
    public string? Password { get; set; }
    public bool AutoGenerate { get; set; } = true;
}
