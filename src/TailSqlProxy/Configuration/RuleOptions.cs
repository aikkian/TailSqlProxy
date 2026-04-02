namespace TailSqlProxy.Configuration;

public class RuleOptions
{
    public UnboundedSelectOptions? UnboundedSelect { get; set; }
    public UnboundedDeleteOptions? UnboundedDelete { get; set; }
    public SsmsMetadataOptions? SsmsMetadata { get; set; }
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
