using FluentAssertions;
using Microsoft.Extensions.Options;
using Prometheus;
using TailSqlProxy.Configuration;
using TailSqlProxy.Monitoring;
using Xunit;

namespace TailSqlProxy.Tests.Monitoring;

public class ProxyMetricsTests : IDisposable
{
    private readonly CollectorRegistry _registry;
    private readonly ProxyMetrics _metrics;

    public ProxyMetricsTests()
    {
        _registry = Metrics.NewCustomRegistry();
        var options = Options.Create(new MetricsOptions
        {
            Enabled = true,
            SlowQueryThresholdMs = 5000,
            DurationBuckets = [0.01, 0.1, 1, 10, 60],
        });
        _metrics = new ProxyMetrics(options, _registry);
    }

    public void Dispose()
    {
        // CollectorRegistry doesn't implement IDisposable, nothing to clean up
    }

    private async Task<string> ExportMetricsText()
    {
        using var ms = new MemoryStream();
        await _registry.CollectAndExportAsTextAsync(ms);
        ms.Position = 0;
        return new StreamReader(ms).ReadToEnd();
    }

    // =============================================
    // QUERY METRICS
    // =============================================

    [Fact]
    public async Task RecordQuery_IncrementsCounter()
    {
        _metrics.RecordQuery("admin", "TestDB", "SSMS", 0.5);
        _metrics.RecordQuery("admin", "TestDB", "SSMS", 1.2);
        _metrics.RecordQuery("analyst", "ProdDB", "MyApp", 0.3);

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_queries_total");
        text.Should().Contain("user=\"admin\"");
        text.Should().Contain("database=\"TestDB\"");
        text.Should().Contain("app=\"SSMS\"");
    }

    [Fact]
    public async Task RecordQuery_RecordsHistogram()
    {
        _metrics.RecordQuery("admin", "TestDB", "SSMS", 0.5);

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_query_duration_seconds_bucket");
        text.Should().Contain("tailsqlproxy_query_duration_seconds_sum");
        text.Should().Contain("tailsqlproxy_query_duration_seconds_count");
    }

    [Fact]
    public async Task RecordQuery_NullLabels_UsesUnknown()
    {
        _metrics.RecordQuery(null, null, null, 0.1);

        var text = await ExportMetricsText();
        text.Should().Contain("user=\"unknown\"");
        text.Should().Contain("database=\"unknown\"");
    }

    // =============================================
    // BLOCKED QUERY METRICS
    // =============================================

    [Fact]
    public async Task RecordBlockedQuery_IncrementsCounter()
    {
        _metrics.RecordBlockedQuery("hacker", "ProdDB", "SqlInjection");
        _metrics.RecordBlockedQuery("hacker", "ProdDB", "SqlInjection");
        _metrics.RecordBlockedQuery("analyst", "ProdDB", "SsmsMetadata");

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_blocked_queries_total");
        text.Should().Contain("rule=\"SqlInjection\"");
        text.Should().Contain("rule=\"SsmsMetadata\"");
    }

    // =============================================
    // SLOW QUERY METRICS
    // =============================================

    [Fact]
    public async Task RecordSlowQuery_IncrementsCounter()
    {
        _metrics.RecordSlowQuery("admin", "TestDB", 10.5);

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_slow_queries_total");
        text.Should().Contain("user=\"admin\"");
    }

    // =============================================
    // CONNECTION METRICS
    // =============================================

    [Fact]
    public async Task ConnectionGauge_IncrementAndDecrement()
    {
        _metrics.IncrementActiveConnections();
        _metrics.IncrementActiveConnections();
        _metrics.IncrementActiveConnections();
        _metrics.DecrementActiveConnections();

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_active_connections 2");
    }

    [Fact]
    public async Task RecordConnection_IncrementsTotal()
    {
        _metrics.RecordConnection();
        _metrics.RecordConnection();

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_connections_total 2");
    }

    [Fact]
    public async Task RecordRejectedConnection_IncrementsTotal()
    {
        _metrics.RecordRejectedConnection();

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_rejected_connections_total 1");
    }

    // =============================================
    // BYTE RELAY METRICS
    // =============================================

    [Fact]
    public async Task RecordBytesRelayed_TracksDirection()
    {
        _metrics.RecordBytesRelayed(1024, "client_to_server");
        _metrics.RecordBytesRelayed(2048, "server_to_client");
        _metrics.RecordBytesRelayed(512, "client_to_server");

        var text = await ExportMetricsText();
        text.Should().Contain("tailsqlproxy_bytes_relayed_total");
        text.Should().Contain("direction=\"client_to_server\"");
        text.Should().Contain("direction=\"server_to_client\"");
    }

    // =============================================
    // HISTOGRAM BUCKET CONFIGURATION
    // =============================================

    [Fact]
    public async Task Histogram_UsesConfiguredBuckets()
    {
        _metrics.RecordQuery("admin", "TestDB", "SSMS", 0.005);

        var text = await ExportMetricsText();
        // Our configured buckets: 0.01, 0.1, 1, 10, 60
        text.Should().Contain("le=\"0.01\"");
        text.Should().Contain("le=\"0.1\"");
        text.Should().Contain("le=\"1\"");
        text.Should().Contain("le=\"10\"");
        text.Should().Contain("le=\"60\"");
    }

    // =============================================
    // NULL METRICS (disabled)
    // =============================================

    [Fact]
    public void NullMetrics_DoesNotThrow()
    {
        var nullMetrics = NullProxyMetrics.Instance;

        // All operations should be no-ops
        nullMetrics.RecordQuery("user", "db", "app", 1.0);
        nullMetrics.RecordBlockedQuery("user", "db", "rule");
        nullMetrics.RecordSlowQuery("user", "db", 10.0);
        nullMetrics.IncrementActiveConnections();
        nullMetrics.DecrementActiveConnections();
        nullMetrics.RecordConnection();
        nullMetrics.RecordRejectedConnection();
        nullMetrics.RecordBytesRelayed(1024, "client_to_server");
    }
}
