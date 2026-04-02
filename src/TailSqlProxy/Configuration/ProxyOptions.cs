namespace TailSqlProxy.Configuration;

public class ProxyOptions
{
    public int ListenPort { get; set; } = 1433;
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int MaxConcurrentConnections { get; set; } = 100;
    public CertificateOptions Certificate { get; set; } = new();
    public string AuditLogPath { get; set; } = "logs/audit-.log";
    public DatadogOptions Datadog { get; set; } = new();
}

public class DatadogOptions
{
    public bool Enabled { get; set; }
    public string ApiKey { get; set; } = string.Empty;
    public string Service { get; set; } = "tailsqlproxy";
    public string Source { get; set; } = "csharp";
    public string? Host { get; set; }
    public string[]? Tags { get; set; }
}

public class CertificateOptions
{
    public string? Path { get; set; }
    public string? Password { get; set; }
    public bool AutoGenerate { get; set; } = true;
}
