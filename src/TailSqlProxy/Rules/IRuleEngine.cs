namespace TailSqlProxy.Rules;

public interface IRuleEngine
{
    RuleResult Evaluate(QueryContext context);
}
