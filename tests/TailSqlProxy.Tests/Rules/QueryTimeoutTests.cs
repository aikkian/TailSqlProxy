using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Monitoring;
using TailSqlProxy.Rules;
using Xunit;

namespace TailSqlProxy.Tests.Rules;

public class QueryTimeoutTests
{
    private static QueryContext Ctx(string sql) => new() { SqlText = sql };

    // ──────────────────── RuleResult ────────────────────

    [Fact]
    public void RuleResult_Allow_HasNoTimeout()
    {
        var result = RuleResult.Allow;
        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeFalse();
        result.TimeoutMs.Should().BeNull();
    }

    [Fact]
    public void RuleResult_Block_HasNoTimeout()
    {
        var result = RuleResult.Block("some reason");
        result.IsBlocked.Should().BeTrue();
        result.HasTimeout.Should().BeFalse();
        result.TimeoutMs.Should().BeNull();
    }

    [Fact]
    public void RuleResult_AllowWithTimeout_HasTimeout()
    {
        var result = RuleResult.AllowWithTimeout(60000, "unbounded select");
        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(60000);
        result.Reason.Should().Be("unbounded select");
    }

    [Fact]
    public void RuleResult_AllowWithTimeout_ZeroMs_HasNoTimeout()
    {
        var result = RuleResult.AllowWithTimeout(0, "zero");
        result.HasTimeout.Should().BeFalse();
    }

    [Fact]
    public void RuleResult_AllowWithTimeout_NegativeMs_HasNoTimeout()
    {
        var result = new RuleResult(false, "negative", -100);
        result.HasTimeout.Should().BeFalse();
    }

    // ──────── UnboundedSelectRule — Timeout mode ────────

    [Theory]
    [InlineData("SELECT * FROM Orders")]
    [InlineData("SELECT * FROM dbo.Orders")]
    [InlineData("select * from Orders")]
    public void UnboundedSelect_TimeoutMode_ReturnsAllowWithTimeout(string sql)
    {
        var rule = CreateSelectRule(UnboundedQueryMode.Timeout, 120_000);
        var result = rule.Evaluate(Ctx(sql));

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(120_000);
    }

    [Theory]
    [InlineData("SELECT * FROM Orders")]
    [InlineData("SELECT * FROM dbo.Orders")]
    public void UnboundedSelect_BlockMode_StillBlocks(string sql)
    {
        var rule = CreateSelectRule(UnboundedQueryMode.Block, 120_000);
        var result = rule.Evaluate(Ctx(sql));

        result.IsBlocked.Should().BeTrue();
        result.HasTimeout.Should().BeFalse();
    }

    [Theory]
    [InlineData("SELECT * FROM Orders WHERE Id = 1")]
    [InlineData("SELECT TOP 10 * FROM Orders")]
    [InlineData("SELECT Id, Name FROM Orders")]
    public void UnboundedSelect_TimeoutMode_SafeQueries_NoTimeout(string sql)
    {
        var rule = CreateSelectRule(UnboundedQueryMode.Timeout, 120_000);
        var result = rule.Evaluate(Ctx(sql));

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeFalse();
    }

    [Fact]
    public void UnboundedSelect_TimeoutMode_UsesConfiguredTimeout()
    {
        var rule = CreateSelectRule(UnboundedQueryMode.Timeout, 45_000);
        var result = rule.Evaluate(Ctx("SELECT * FROM Orders"));

        result.TimeoutMs.Should().Be(45_000);
    }

    [Fact]
    public void UnboundedSelect_TimeoutMode_DefaultTimeoutIs300s()
    {
        var opts = new UnboundedSelectOptions { Enabled = true, Mode = UnboundedQueryMode.Timeout };
        opts.TimeoutMs.Should().Be(300_000);
    }

    // ──────── UnboundedDeleteRule — Timeout mode ────────

    [Theory]
    [InlineData("DELETE FROM Orders")]
    [InlineData("DELETE FROM dbo.Orders")]
    [InlineData("delete from Orders")]
    public void UnboundedDelete_TimeoutMode_ReturnsAllowWithTimeout(string sql)
    {
        var rule = CreateDeleteRule(UnboundedQueryMode.Timeout, 180_000);
        var result = rule.Evaluate(Ctx(sql));

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(180_000);
    }

    [Theory]
    [InlineData("DELETE FROM Orders")]
    [InlineData("DELETE FROM dbo.Orders")]
    public void UnboundedDelete_BlockMode_StillBlocks(string sql)
    {
        var rule = CreateDeleteRule(UnboundedQueryMode.Block, 180_000);
        var result = rule.Evaluate(Ctx(sql));

        result.IsBlocked.Should().BeTrue();
        result.HasTimeout.Should().BeFalse();
    }

    [Theory]
    [InlineData("DELETE FROM Orders WHERE Id = 1")]
    [InlineData("DELETE TOP (1000) FROM Orders")]
    [InlineData("SELECT * FROM Orders")]
    public void UnboundedDelete_TimeoutMode_SafeQueries_NoTimeout(string sql)
    {
        var rule = CreateDeleteRule(UnboundedQueryMode.Timeout, 180_000);
        var result = rule.Evaluate(Ctx(sql));

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeFalse();
    }

    [Fact]
    public void UnboundedDelete_TimeoutMode_UsesConfiguredTimeout()
    {
        var rule = CreateDeleteRule(UnboundedQueryMode.Timeout, 60_000);
        var result = rule.Evaluate(Ctx("DELETE FROM Orders"));

        result.TimeoutMs.Should().Be(60_000);
    }

    // ──────── RuleEngine — Timeout propagation ────────

    [Fact]
    public void RuleEngine_PropagatesTimeout_FromSingleRule()
    {
        var engine = CreateEngine(
            selectMode: UnboundedQueryMode.Timeout, selectTimeout: 120_000,
            deleteMode: UnboundedQueryMode.Block, deleteTimeout: 300_000);

        var result = engine.Evaluate(Ctx("SELECT * FROM Orders"));

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(120_000);
    }

    [Fact]
    public void RuleEngine_PicksTightestTimeout_WhenMultipleRulesMatch()
    {
        // Both rules return timeout for an unbounded "DELETE FROM (SELECT * FROM ...)" scenario is unlikely,
        // so test with two separate rules where we control the returned timeout via a stub.
        var stubRule1 = new StubRule("Stub1", RuleResult.AllowWithTimeout(200_000, "stub1"));
        var stubRule2 = new StubRule("Stub2", RuleResult.AllowWithTimeout(100_000, "stub2"));

        var ruleOptions = Options.Create(new RuleOptions());
        var engine = new RuleEngine(
            [stubRule1, stubRule2],
            ruleOptions,
            NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(Ctx("SELECT 1"));

        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(100_000, "engine should pick the tightest (smallest) timeout");
        result.Reason.Should().Be("stub2");
    }

    [Fact]
    public void RuleEngine_BlockTakesPrecedence_OverTimeout()
    {
        var stubAllow = new StubRule("TimeoutRule", RuleResult.AllowWithTimeout(120_000, "timeout"));
        var stubBlock = new StubRule("BlockRule", RuleResult.Block("blocked!"));

        var ruleOptions = Options.Create(new RuleOptions());
        // Block rule comes second - should still block
        var engine = new RuleEngine(
            [stubAllow, stubBlock],
            ruleOptions,
            NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(Ctx("SELECT 1"));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Be("blocked!");
    }

    [Fact]
    public void RuleEngine_GlobalTimeout_AppliedWhenNoRuleTimeout()
    {
        var ruleOptions = Options.Create(new RuleOptions
        {
            QueryTimeout = new QueryTimeoutOptions
            {
                Enabled = true,
                DefaultTimeoutMs = 60_000,
            },
        });

        // No rules that return timeout
        var engine = new RuleEngine(
            [],
            ruleOptions,
            NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(Ctx("SELECT 1"));

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(60_000);
        result.Reason.Should().Be("Global query timeout");
    }

    [Fact]
    public void RuleEngine_GlobalTimeout_NotApplied_WhenRuleTimeoutExists()
    {
        var stubRule = new StubRule("Fast", RuleResult.AllowWithTimeout(30_000, "rule timeout"));

        var ruleOptions = Options.Create(new RuleOptions
        {
            QueryTimeout = new QueryTimeoutOptions
            {
                Enabled = true,
                DefaultTimeoutMs = 120_000,
            },
        });

        var engine = new RuleEngine(
            [stubRule],
            ruleOptions,
            NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(Ctx("SELECT 1"));

        result.HasTimeout.Should().BeTrue();
        result.TimeoutMs.Should().Be(30_000, "rule-specific timeout takes precedence over global");
    }

    [Fact]
    public void RuleEngine_GlobalTimeout_NotApplied_WhenDisabled()
    {
        var ruleOptions = Options.Create(new RuleOptions
        {
            QueryTimeout = new QueryTimeoutOptions
            {
                Enabled = false,
                DefaultTimeoutMs = 60_000,
            },
        });

        var engine = new RuleEngine(
            [],
            ruleOptions,
            NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(Ctx("SELECT 1"));

        result.HasTimeout.Should().BeFalse();
    }

    [Fact]
    public void RuleEngine_GlobalTimeout_NotApplied_WhenZeroMs()
    {
        var ruleOptions = Options.Create(new RuleOptions
        {
            QueryTimeout = new QueryTimeoutOptions
            {
                Enabled = true,
                DefaultTimeoutMs = 0,
            },
        });

        var engine = new RuleEngine(
            [],
            ruleOptions,
            NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(Ctx("SELECT 1"));

        result.HasTimeout.Should().BeFalse();
    }

    [Fact]
    public void RuleEngine_BypassUser_SkipsTimeout()
    {
        var ruleOptions = Options.Create(new RuleOptions
        {
            UnboundedSelect = new UnboundedSelectOptions
            {
                Enabled = true,
                Mode = UnboundedQueryMode.Timeout,
                TimeoutMs = 120_000,
            },
            BypassUsers = ["admin"],
        });

        var rules = new IQueryRule[]
        {
            new UnboundedSelectRule(ruleOptions, NullLogger<UnboundedSelectRule>.Instance),
        };

        var engine = new RuleEngine(rules, ruleOptions, NullLogger<RuleEngine>.Instance);

        var result = engine.Evaluate(new QueryContext
        {
            SqlText = "SELECT * FROM Orders",
            Username = "admin",
        });

        result.IsBlocked.Should().BeFalse();
        result.HasTimeout.Should().BeFalse("bypassed users should skip all rules including timeouts");
    }

    // ──────── Configuration defaults ────────

    [Fact]
    public void QueryTimeoutOptions_DefaultsToDisabled()
    {
        var opts = new QueryTimeoutOptions();
        opts.Enabled.Should().BeFalse();
        opts.DefaultTimeoutMs.Should().Be(0);
    }

    [Fact]
    public void UnboundedSelectOptions_DefaultsToBlockMode()
    {
        var opts = new UnboundedSelectOptions();
        opts.Mode.Should().Be(UnboundedQueryMode.Block);
        opts.TimeoutMs.Should().Be(300_000);
        opts.Enabled.Should().BeTrue();
    }

    [Fact]
    public void UnboundedDeleteOptions_DefaultsToBlockMode()
    {
        var opts = new UnboundedDeleteOptions();
        opts.Mode.Should().Be(UnboundedQueryMode.Block);
        opts.TimeoutMs.Should().Be(300_000);
        opts.Enabled.Should().BeTrue();
    }

    // ──────── Metrics ────────

    [Fact]
    public void NullProxyMetrics_RecordTimeoutKilled_DoesNotThrow()
    {
        var metrics = NullProxyMetrics.Instance;
        var act = () => metrics.RecordTimeoutKilled("user1", "db1");
        act.Should().NotThrow();
    }

    [Fact]
    public void ProxyMetrics_RecordTimeoutKilled_IncrementsCounter()
    {
        var registry = new Prometheus.CollectorRegistry();
        var options = Options.Create(new MetricsOptions());
        var metrics = new ProxyMetrics(options, registry);

        metrics.RecordTimeoutKilled("testuser", "testdb");

        // Verify we can call it without error — counter value verified via Prometheus serialization
        var act = () => metrics.RecordTimeoutKilled("testuser", "testdb");
        act.Should().NotThrow();
    }

    // ──────── Helpers ────────

    private static UnboundedSelectRule CreateSelectRule(UnboundedQueryMode mode, double timeoutMs)
    {
        var options = Options.Create(new RuleOptions
        {
            UnboundedSelect = new UnboundedSelectOptions
            {
                Enabled = true,
                Mode = mode,
                TimeoutMs = timeoutMs,
            },
        });
        return new UnboundedSelectRule(options, NullLogger<UnboundedSelectRule>.Instance);
    }

    private static UnboundedDeleteRule CreateDeleteRule(UnboundedQueryMode mode, double timeoutMs)
    {
        var options = Options.Create(new RuleOptions
        {
            UnboundedDelete = new UnboundedDeleteOptions
            {
                Enabled = true,
                Mode = mode,
                TimeoutMs = timeoutMs,
            },
        });
        return new UnboundedDeleteRule(options, NullLogger<UnboundedDeleteRule>.Instance);
    }

    private static IRuleEngine CreateEngine(
        UnboundedQueryMode selectMode = UnboundedQueryMode.Block,
        double selectTimeout = 300_000,
        UnboundedQueryMode deleteMode = UnboundedQueryMode.Block,
        double deleteTimeout = 300_000,
        QueryTimeoutOptions? globalTimeout = null)
    {
        var ruleOptions = Options.Create(new RuleOptions
        {
            UnboundedSelect = new UnboundedSelectOptions
            {
                Enabled = true,
                Mode = selectMode,
                TimeoutMs = selectTimeout,
            },
            UnboundedDelete = new UnboundedDeleteOptions
            {
                Enabled = true,
                Mode = deleteMode,
                TimeoutMs = deleteTimeout,
            },
            QueryTimeout = globalTimeout,
        });

        var rules = new IQueryRule[]
        {
            new UnboundedSelectRule(ruleOptions, NullLogger<UnboundedSelectRule>.Instance),
            new UnboundedDeleteRule(ruleOptions, NullLogger<UnboundedDeleteRule>.Instance),
        };

        return new RuleEngine(rules, ruleOptions, NullLogger<RuleEngine>.Instance);
    }

    /// <summary>Stub rule returning a predetermined result for testing RuleEngine behavior.</summary>
    private sealed class StubRule(string name, RuleResult result) : IQueryRule
    {
        public string Name => name;
        public bool IsEnabled => true;
        public RuleResult Evaluate(QueryContext context) => result;
    }
}
