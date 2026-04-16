namespace TailSqlProxy.Monitoring;

/// <summary>
/// Records proxy-level metrics: query performance, connections, blocked queries.
/// Backed by Prometheus counters, histograms, and gauges.
/// </summary>
public interface IProxyMetrics
{
    /// <summary>Record a completed query with its duration.</summary>
    void RecordQuery(string? user, string? database, string? appName, double durationSeconds);

    /// <summary>Record a query blocked by a rule.</summary>
    void RecordBlockedQuery(string? user, string? database, string ruleName);

    /// <summary>Record a slow query (above threshold).</summary>
    void RecordSlowQuery(string? user, string? database, double durationSeconds);

    /// <summary>Record a query killed by timeout enforcement.</summary>
    void RecordTimeoutKilled(string? user, string? database);

    /// <summary>Increment active connection gauge.</summary>
    void IncrementActiveConnections();

    /// <summary>Decrement active connection gauge.</summary>
    void DecrementActiveConnections();

    /// <summary>Record a new connection.</summary>
    void RecordConnection();

    /// <summary>Record a rejected connection (max limit reached).</summary>
    void RecordRejectedConnection();

    /// <summary>Record bytes relayed through the proxy.</summary>
    void RecordBytesRelayed(long bytes, string direction);
}
