namespace TailSqlProxy.Configuration;

public class RuleOptions
{
    public UnboundedSelectOptions? UnboundedSelect { get; set; }
    public UnboundedDeleteOptions? UnboundedDelete { get; set; }
    public SsmsMetadataOptions? SsmsMetadata { get; set; }

    /// <summary>
    /// Users in this list bypass all query blocking rules.
    /// Matched case-insensitively against the Login7 username.
    /// Example: ["admin_user", "deploy_svc"]
    /// </summary>
    public string[] BypassUsers { get; set; } = [];

    /// <summary>
    /// Application names in this list bypass all query blocking rules.
    /// Matched case-insensitively against the Login7 app name.
    /// Example: ["MyDeployTool", "DataMigrator"]
    /// </summary>
    public string[] BypassAppNames { get; set; } = [];

    /// <summary>
    /// Client IPs in this list bypass all query blocking rules.
    /// Example: ["10.0.0.50", "192.168.1.100"]
    /// </summary>
    public string[] BypassClientIps { get; set; } = [];
}

public class UnboundedSelectOptions
{
    public bool Enabled { get; set; } = true;
}

public class UnboundedDeleteOptions
{
    public bool Enabled { get; set; } = true;
}

public class SsmsMetadataOptions
{
    public bool Enabled { get; set; } = true;
    public string[]? BlockedProcedures { get; set; }
    public string[]? BlockedSystemViews { get; set; }
    public string[]? BlockedSchemas { get; set; }
    public string[]? AllowedPatterns { get; set; }
}
