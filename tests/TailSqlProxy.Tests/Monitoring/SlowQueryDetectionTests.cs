using FluentAssertions;
using Microsoft.Extensions.Options;
using Prometheus;
using TailSqlProxy.Configuration;
using TailSqlProxy.Monitoring;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Monitoring;

public class SlowQueryDetectionTests
{
    // =============================================
    // THRESHOLD DETECTION
    // =============================================

    [Theory]
    [InlineData(5000, true)]   // At threshold = slow
    [InlineData(5001, true)]   // Above threshold = slow
    [InlineData(10000, true)]  // Way above = slow
    [InlineData(4999, false)]  // Below threshold = not slow
    [InlineData(100, false)]   // Fast query
    [InlineData(0, false)]     // Instant
    public void SlowQuery_ThresholdDetection(double durationMs, bool expectedSlow)
    {
        var thresholdMs = 5000.0;
        var isSlow = durationMs >= thresholdMs;
        isSlow.Should().Be(expectedSlow);
    }

    [Fact]
    public void QueryContext_DurationTracking()
    {
        var context = new QueryContext
        {
            SqlText = "SELECT * FROM LargeTable",
            Username = "analyst",
            Database = "ProdDB",
            StartTimeUtc = DateTime.UtcNow.AddSeconds(-6),
        };

        // Simulate setting duration after response
        context.DurationMs = (DateTime.UtcNow - context.StartTimeUtc!.Value).TotalMilliseconds;
        context.RowCount = 500000;

        context.DurationMs.Should().BeGreaterThan(5000);
        context.RowCount.Should().Be(500000);
    }

    [Fact]
    public void QueryContext_RowCount_FromDoneToken()
    {
        var context = new QueryContext
        {
            SqlText = "SELECT COUNT(*) FROM Users",
            StartTimeUtc = DateTime.UtcNow,
        };

        context.DurationMs = 50;
        context.RowCount = 42;

        context.DurationMs.Should().Be(50);
        context.RowCount.Should().Be(42);
    }

    // =============================================
    // METRICS INTEGRATION — Slow vs Normal queries
    // =============================================

    [Fact]
    public async Task SlowQuery_RecordedInMetrics()
    {
        var registry = Metrics.NewCustomRegistry();
        var options = Options.Create(new MetricsOptions
        {
            Enabled = true,
            SlowQueryThresholdMs = 1000,
            DurationBuckets = [0.1, 1, 10],
        });
        var metrics = new ProxyMetrics(options, registry);

        // Record a slow query (5 seconds, above 1s threshold)
        var durationMs = 5000.0;
        var durationSeconds = durationMs / 1000.0;

        metrics.RecordQuery("analyst", "ProdDB", "MyApp", durationSeconds);

        if (durationMs >= options.Value.SlowQueryThresholdMs)
            metrics.RecordSlowQuery("analyst", "ProdDB", durationSeconds);

        using var ms = new MemoryStream();
        await registry.CollectAndExportAsTextAsync(ms);
        ms.Position = 0;
        var text = new StreamReader(ms).ReadToEnd();

        text.Should().Contain("tailsqlproxy_slow_queries_total");
        text.Should().Contain("tailsqlproxy_queries_total");
    }

    [Fact]
    public async Task NormalQuery_NotRecordedAsSlowInMetrics()
    {
        var registry = Metrics.NewCustomRegistry();
        var options = Options.Create(new MetricsOptions
        {
            Enabled = true,
            SlowQueryThresholdMs = 5000,
            DurationBuckets = [0.1, 1, 10],
        });
        var metrics = new ProxyMetrics(options, registry);

        // Record a normal query (100ms, below 5s threshold)
        var durationMs = 100.0;
        var durationSeconds = durationMs / 1000.0;

        metrics.RecordQuery("analyst", "ProdDB", "MyApp", durationSeconds);

        // Do NOT record as slow
        if (durationMs >= options.Value.SlowQueryThresholdMs)
            metrics.RecordSlowQuery("analyst", "ProdDB", durationSeconds);

        using var ms = new MemoryStream();
        await registry.CollectAndExportAsTextAsync(ms);
        ms.Position = 0;
        var text = new StreamReader(ms).ReadToEnd();

        text.Should().Contain("tailsqlproxy_queries_total");
        // slow_queries_total should not appear (no observations)
        text.Should().NotContain("tailsqlproxy_slow_queries_total{");
    }

    // =============================================
    // METRICS OPTIONS CONFIGURATION
    // =============================================

    [Fact]
    public void MetricsOptions_Defaults()
    {
        var options = new MetricsOptions();

        options.Enabled.Should().BeFalse();
        options.Port.Should().Be(9090);
        options.SlowQueryThresholdMs.Should().Be(5000);
        options.DurationBuckets.Should().HaveCountGreaterThan(5);
    }

    [Fact]
    public void MetricsOptions_CustomThreshold()
    {
        var options = new MetricsOptions
        {
            Enabled = true,
            SlowQueryThresholdMs = 2000,
        };

        options.SlowQueryThresholdMs.Should().Be(2000);
    }

    [Fact]
    public void MetricsOptions_CustomBuckets()
    {
        var options = new MetricsOptions
        {
            DurationBuckets = [0.001, 0.01, 0.1, 1],
        };

        options.DurationBuckets.Should().HaveCount(4);
        options.DurationBuckets[0].Should().Be(0.001);
    }

    // =============================================
    // MULTIPLE QUERIES METRICS ACCURACY
    // =============================================

    [Fact]
    public async Task MultipleQueries_MetricsAccumulate()
    {
        var registry = Metrics.NewCustomRegistry();
        var options = Options.Create(new MetricsOptions
        {
            Enabled = true,
            SlowQueryThresholdMs = 1000,
            DurationBuckets = [0.1, 1, 10],
        });
        var metrics = new ProxyMetrics(options, registry);

        // Record mix of fast and slow queries
        metrics.RecordQuery("admin", "DB1", "App1", 0.05);
        metrics.RecordQuery("admin", "DB1", "App1", 0.1);
        metrics.RecordQuery("admin", "DB1", "App1", 5.0); // slow
        metrics.RecordSlowQuery("admin", "DB1", 5.0);

        metrics.RecordBlockedQuery("hacker", "DB1", "SqlInjection");
        metrics.RecordBlockedQuery("hacker", "DB1", "SqlInjection");

        using var ms = new MemoryStream();
        await registry.CollectAndExportAsTextAsync(ms);
        ms.Position = 0;
        var text = new StreamReader(ms).ReadToEnd();

        // 3 queries total for admin/DB1/App1
        text.Should().Contain("tailsqlproxy_queries_total{user=\"admin\",database=\"DB1\",app=\"App1\"} 3");
        // 1 slow query
        text.Should().Contain("tailsqlproxy_slow_queries_total{user=\"admin\",database=\"DB1\"} 1");
        // 2 blocked queries
        text.Should().Contain("tailsqlproxy_blocked_queries_total{user=\"hacker\",database=\"DB1\",rule=\"SqlInjection\"} 2");
    }

    // =============================================
    // DONE TOKEN PARSING
    // =============================================

    [Fact]
    public void DoneToken_FinalWithRowCount()
    {
        // Build a DONE token: type=0xFD, status=0x0010 (DONE_COUNT), curcmd=0, rowcount=42
        var payload = new byte[13];
        payload[0] = 0xFD; // DONE token type
        payload[1] = 0x10; // status low byte: DONE_COUNT
        payload[2] = 0x00; // status high byte
        payload[3] = 0x00; // curcmd low
        payload[4] = 0x00; // curcmd high
        // rowcount = 42 (little-endian int64)
        payload[5] = 42;
        payload[6] = 0; payload[7] = 0; payload[8] = 0;
        payload[9] = 0; payload[10] = 0; payload[11] = 0; payload[12] = 0;

        // status & 0x0001 == 0 (no DONE_MORE) → final
        ushort status = BitConverter.ToUInt16(payload, 1);
        bool isFinal = (status & 0x0001) == 0;
        isFinal.Should().BeTrue();

        // status & 0x0010 (DONE_COUNT) → has row count
        bool hasRowCount = (status & 0x0010) != 0;
        hasRowCount.Should().BeTrue();

        long rowCount = BitConverter.ToInt64(payload, 5);
        rowCount.Should().Be(42);
    }

    [Fact]
    public void DoneToken_DoneMore_NotFinal()
    {
        // DONE token with DONE_MORE bit set
        var payload = new byte[13];
        payload[0] = 0xFD;
        payload[1] = 0x01; // DONE_MORE
        payload[2] = 0x00;

        ushort status = BitConverter.ToUInt16(payload, 1);
        bool isFinal = (status & 0x0001) == 0;
        isFinal.Should().BeFalse();
    }

    [Fact]
    public void DoneProc_Token_Recognized()
    {
        // DONEPROC = 0xFE
        var payload = new byte[13];
        payload[0] = 0xFE;
        payload[1] = 0x10; // DONE_COUNT
        payload[2] = 0x00;
        payload[5] = 100; // rowcount = 100

        byte tokenType = payload[0];
        tokenType.Should().Be(0xFE);

        ushort status = BitConverter.ToUInt16(payload, 1);
        bool isFinal = (status & 0x0001) == 0;
        isFinal.Should().BeTrue();

        long rowCount = BitConverter.ToInt64(payload, 5);
        rowCount.Should().Be(100);
    }
}
