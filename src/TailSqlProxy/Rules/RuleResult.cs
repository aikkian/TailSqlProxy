namespace TailSqlProxy.Rules;

public sealed record RuleResult(bool IsBlocked, string? Reason = null, double? TimeoutMs = null)
{
    /// <summary>Query is allowed with no timeout enforcement.</summary>
    public static RuleResult Allow => new(false);

    /// <summary>Query is blocked immediately.</summary>
    public static RuleResult Block(string reason) => new(true, reason);

    /// <summary>
    /// Query is allowed but will be killed if it exceeds the specified timeout.
    /// The proxy sends a TDS Attention signal to cancel the query on the server.
    /// </summary>
    public static RuleResult AllowWithTimeout(double timeoutMs, string reason)
        => new(false, reason, timeoutMs);

    /// <summary>True if this result enforces a runtime timeout on the query.</summary>
    public bool HasTimeout => TimeoutMs.HasValue && TimeoutMs.Value > 0;
}
