namespace TailSqlProxy.Configuration;

/// <summary>
/// Configuration for read/write split routing.
/// When enabled, pure SELECT queries (no active transaction) are routed
/// to a read-only replica via ApplicationIntent=ReadOnly.
/// </summary>
public class ReadWriteSplitOptions
{
    public bool Enabled { get; set; }

    /// <summary>
    /// Hostname of the read-only replica. If empty, uses the same host as TargetServer
    /// (Azure SQL read-scale-out uses the same hostname with ApplicationIntent=ReadOnly).
    /// </summary>
    public string? ReadOnlyHost { get; set; }

    /// <summary>Port for the read-only replica. Default: 1433.</summary>
    public int ReadOnlyPort { get; set; } = 1433;

    /// <summary>
    /// App names that always route to primary (read-write), regardless of query type.
    /// Example: ["MigrationTool", "DeployService"]
    /// </summary>
    public string[] AlwaysPrimaryAppNames { get; set; } = [];

    /// <summary>
    /// App names that always route to read-only replica.
    /// Example: ["PowerBI", "ReportingService"]
    /// </summary>
    public string[] AlwaysReadOnlyAppNames { get; set; } = [];
}
