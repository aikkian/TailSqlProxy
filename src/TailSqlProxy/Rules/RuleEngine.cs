using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

public class RuleEngine : IRuleEngine
{
    private readonly IReadOnlyList<IQueryRule> _rules;
    private readonly RuleOptions _options;
    private readonly ILogger<RuleEngine> _logger;

    private readonly HashSet<string> _bypassUsers;
    private readonly HashSet<string> _bypassAppNames;
    private readonly HashSet<string> _bypassClientIps;

    public RuleEngine(IEnumerable<IQueryRule> rules, IOptions<RuleOptions> options, ILogger<RuleEngine> logger)
    {
        _rules = rules.ToList();
        _options = options.Value;
        _logger = logger;

        _bypassUsers = new HashSet<string>(_options.BypassUsers, StringComparer.OrdinalIgnoreCase);
        _bypassAppNames = new HashSet<string>(_options.BypassAppNames, StringComparer.OrdinalIgnoreCase);
        _bypassClientIps = new HashSet<string>(_options.BypassClientIps, StringComparer.Ordinal);
    }

    public RuleResult Evaluate(QueryContext context)
    {
        // Check if this session is allowed to bypass all rules
        if (IsBypassed(context))
            return RuleResult.Allow;

        RuleResult? timeoutResult = null;

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

            // Track the tightest (smallest) timeout from any rule
            if (result.HasTimeout)
            {
                if (timeoutResult == null || result.TimeoutMs!.Value < timeoutResult.TimeoutMs!.Value)
                    timeoutResult = result;
            }
        }

        // Apply global default timeout if no rule-specific timeout was set
        if (timeoutResult == null && _options.QueryTimeout is { Enabled: true, DefaultTimeoutMs: > 0 })
        {
            return RuleResult.AllowWithTimeout(
                _options.QueryTimeout.DefaultTimeoutMs,
                "Global query timeout");
        }

        return timeoutResult ?? RuleResult.Allow;
    }

    private bool IsBypassed(QueryContext context)
    {
        if (context.Username is not null && _bypassUsers.Contains(context.Username))
        {
            _logger.LogDebug("User {Username} bypasses rule evaluation (in BypassUsers list)", context.Username);
            return true;
        }

        if (context.AppName is not null && _bypassAppNames.Contains(context.AppName))
        {
            _logger.LogDebug("App {AppName} bypasses rule evaluation (in BypassAppNames list)", context.AppName);
            return true;
        }

        if (context.ClientIp is not null && _bypassClientIps.Contains(context.ClientIp))
        {
            _logger.LogDebug("Client IP {ClientIp} bypasses rule evaluation (in BypassClientIps list)", context.ClientIp);
            return true;
        }

        return false;
    }
}
