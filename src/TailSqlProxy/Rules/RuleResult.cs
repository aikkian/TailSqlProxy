namespace TailSqlProxy.Rules;

public sealed record RuleResult(bool IsBlocked, string? Reason = null)
{
    public static RuleResult Allow => new(false);
    public static RuleResult Block(string reason) => new(true, reason);
}
