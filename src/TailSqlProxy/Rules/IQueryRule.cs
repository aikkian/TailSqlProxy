namespace TailSqlProxy.Rules;

public interface IQueryRule
{
    string Name { get; }
    bool IsEnabled { get; }
    RuleResult Evaluate(QueryContext context);
}
