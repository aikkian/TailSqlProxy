namespace TailSqlProxy.Monitoring;

/// <summary>
/// No-op metrics implementation used when metrics are disabled.
/// </summary>
public sealed class NullProxyMetrics : IProxyMetrics
{
    public static readonly NullProxyMetrics Instance = new();

    public void RecordQuery(string? user, string? database, string? appName, double durationSeconds) { }
    public void RecordBlockedQuery(string? user, string? database, string ruleName) { }
    public void RecordSlowQuery(string? user, string? database, double durationSeconds) { }
    public void IncrementActiveConnections() { }
    public void DecrementActiveConnections() { }
    public void RecordConnection() { }
    public void RecordRejectedConnection() { }
    public void RecordBytesRelayed(long bytes, string direction) { }
}
