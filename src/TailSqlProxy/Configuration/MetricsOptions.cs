namespace TailSqlProxy.Configuration;

public class MetricsOptions
{
    /// <summary>Enable Prometheus metrics endpoint and query performance monitoring.</summary>
    public bool Enabled { get; set; }

    /// <summary>HTTP port for the Prometheus /metrics endpoint.</summary>
    public int Port { get; set; } = 9090;

    /// <summary>Queries exceeding this duration (ms) are logged as slow queries.</summary>
    public double SlowQueryThresholdMs { get; set; } = 3_600_000;

    /// <summary>
    /// Histogram bucket boundaries (in seconds) for query duration distribution.
    /// Default covers sub-ms to 60s.
    /// </summary>
    public double[] DurationBuckets { get; set; } =
        [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60];
}
