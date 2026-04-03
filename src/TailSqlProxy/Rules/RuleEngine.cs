using Microsoft.Extensions.Logging;

namespace TailSqlProxy.Rules;

public class RuleEngine : IRuleEngine
{
    private readonly IReadOnlyList<IQueryRule> _rules;
    private readonly ILogger<RuleEngine> _logger;

    public RuleEngine(IEnumerable<IQueryRule> rules, ILogger<RuleEngine> logger)
    {
        _rules = rules.ToList();
        _logger = logger;
    }

    public RuleResult Evaluate(QueryContext context)
    {
        foreach (var rule in _rules)
        {
            if (!rule.IsEnabled)
                continue;

            var result = rule.Evaluate(context);
            if (result.IsBlocked)
            {
                _logger.LogWarning("Query blocked by rule {RuleName}: {Reason} | User={Username} | IP={ClientIp}",
                    rule.Name, result.Reason, context.Username, context.ClientIp);
                return result;
            }
        }

        return RuleResult.Allow;
    }
}
