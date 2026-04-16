using Microsoft.Extensions.Options;
using Prometheus;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Monitoring;

/// <summary>
/// Prometheus-backed metrics for the TDS proxy. All metrics use the "tailsqlproxy_" prefix.
/// Exposed via HTTP /metrics endpoint for Prometheus scraping.
/// </summary>
public sealed class ProxyMetrics : IProxyMetrics
{
    private readonly Counter _queriesTotal;
    private readonly Counter _blockedQueriesTotal;
    private readonly Counter _slowQueriesTotal;
    private readonly Histogram _queryDurationSeconds;
    private readonly Gauge _activeConnections;
    private readonly Counter _connectionsTotal;
    private readonly Counter _rejectedConnectionsTotal;
    private readonly Counter _bytesRelayedTotal;
    private readonly Counter _timeoutKilledTotal;

    public ProxyMetrics(IOptions<MetricsOptions> options)
        : this(options, Metrics.DefaultRegistry)
    {
    }

    /// <summary>Constructor accepting a custom registry (for testing).</summary>
    internal ProxyMetrics(IOptions<MetricsOptions> options, CollectorRegistry registry)
    {
        var metricsOptions = options.Value;
        var factory = Metrics.WithCustomRegistry(registry);

        _queriesTotal = factory.CreateCounter(
            "tailsqlproxy_queries_total",
            "Total number of queries processed by the proxy.",
            new CounterConfiguration
            {
                LabelNames = ["user", "database", "app"]
            });

        _blockedQueriesTotal = factory.CreateCounter(
            "tailsqlproxy_blocked_queries_total",
            "Total number of queries blocked by rules.",
            new CounterConfiguration
            {
                LabelNames = ["user", "database", "rule"]
            });

        _slowQueriesTotal = factory.CreateCounter(
            "tailsqlproxy_slow_queries_total",
            "Total number of queries exceeding the slow query threshold.",
            new CounterConfiguration
            {
                LabelNames = ["user", "database"]
            });

        _queryDurationSeconds = factory.CreateHistogram(
            "tailsqlproxy_query_duration_seconds",
            "Query duration in seconds.",
            new HistogramConfiguration
            {
                LabelNames = ["user", "database"],
                Buckets = metricsOptions.DurationBuckets
            });

        _activeConnections = factory.CreateGauge(
            "tailsqlproxy_active_connections",
            "Number of currently active client connections.");

        _connectionsTotal = factory.CreateCounter(
            "tailsqlproxy_connections_total",
            "Total number of client connections accepted.");

        _rejectedConnectionsTotal = factory.CreateCounter(
            "tailsqlproxy_rejected_connections_total",
            "Total number of connections rejected due to max limit.");

        _bytesRelayedTotal = factory.CreateCounter(
            "tailsqlproxy_bytes_relayed_total",
            "Total bytes relayed through the proxy.",
            new CounterConfiguration
            {
                LabelNames = ["direction"] // "client_to_server" or "server_to_client"
            });

        _timeoutKilledTotal = factory.CreateCounter(
            "tailsqlproxy_timeout_killed_total",
            "Total number of queries killed by timeout enforcement.",
            new CounterConfiguration
            {
                LabelNames = ["user", "database"]
            });
    }

    public void RecordQuery(string? user, string? database, string? appName, double durationSeconds)
    {
        var u = user ?? "unknown";
        var db = database ?? "unknown";
        var app = appName ?? "unknown";

        _queriesTotal.WithLabels(u, db, app).Inc();
        _queryDurationSeconds.WithLabels(u, db).Observe(durationSeconds);
    }

    public void RecordBlockedQuery(string? user, string? database, string ruleName)
    {
        _blockedQueriesTotal.WithLabels(user ?? "unknown", database ?? "unknown", ruleName).Inc();
    }

    public void RecordSlowQuery(string? user, string? database, double durationSeconds)
    {
        _slowQueriesTotal.WithLabels(user ?? "unknown", database ?? "unknown").Inc();
    }

    public void IncrementActiveConnections() => _activeConnections.Inc();
    public void DecrementActiveConnections() => _activeConnections.Dec();
    public void RecordConnection() => _connectionsTotal.Inc();
    public void RecordRejectedConnection() => _rejectedConnectionsTotal.Inc();

    public void RecordTimeoutKilled(string? user, string? database)
    {
        _timeoutKilledTotal.WithLabels(user ?? "unknown", database ?? "unknown").Inc();
    }

    public void RecordBytesRelayed(long bytes, string direction)
    {
        _bytesRelayedTotal.WithLabels(direction).Inc(bytes);
    }
}
