using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.SqlServer.TransactSql.ScriptDom;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

public class UnboundedDeleteRule : IQueryRule
{
    private readonly ILogger<UnboundedDeleteRule> _logger;
    private readonly UnboundedQueryMode _mode;
    private readonly double _timeoutMs;

    public string Name => "UnboundedDelete";
    public bool IsEnabled { get; }

    public UnboundedDeleteRule(IOptions<RuleOptions> options, ILogger<UnboundedDeleteRule> logger)
    {
        _logger = logger;
        var opts = options.Value.UnboundedDelete;
        IsEnabled = opts?.Enabled ?? true;
        _mode = opts?.Mode ?? UnboundedQueryMode.Block;
        _timeoutMs = opts?.TimeoutMs ?? 300_000;
    }

    public RuleResult Evaluate(QueryContext context)
    {
        if (!IsEnabled)
            return RuleResult.Allow;

        if (string.IsNullOrWhiteSpace(context.SqlText))
            return RuleResult.Allow;

        if (context.IsRpc && !string.Equals(context.ProcedureName, "sp_executesql", StringComparison.OrdinalIgnoreCase))
            return RuleResult.Allow;

        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(context.SqlText);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return RuleResult.Allow;

        var visitor = new UnboundedDeleteVisitor();
        fragment.Accept(visitor);

        if (visitor.HasViolation)
        {
            var reason = $"DELETE without WHERE or TOP clause. Fragment: {visitor.OffendingFragment}";
            return _mode == UnboundedQueryMode.Timeout
                ? RuleResult.AllowWithTimeout(_timeoutMs, reason)
                : RuleResult.Block(reason);
        }

        return RuleResult.Allow;
    }

    private class UnboundedDeleteVisitor : TSqlFragmentVisitor
    {
        public bool HasViolation { get; private set; }
        public string? OffendingFragment { get; private set; }

        public override void Visit(DeleteSpecification node)
        {
            if (HasViolation)
                return;

            // Block if no WHERE and no TOP
            if (node.WhereClause == null && node.TopRowFilter == null)
            {
                HasViolation = true;
                OffendingFragment = GetFragmentText(node);
            }
        }

        private static string GetFragmentText(TSqlFragment fragment)
        {
            var text = string.Empty;
            if (fragment.FirstTokenIndex >= 0 && fragment.LastTokenIndex >= 0)
            {
                var tokens = new List<string>();
                for (int i = fragment.FirstTokenIndex; i <= fragment.LastTokenIndex && i < fragment.ScriptTokenStream.Count; i++)
                {
                    tokens.Add(fragment.ScriptTokenStream[i].Text);
                }
                text = string.Join("", tokens);
            }
            return text.Length > 200 ? text[..200] + "..." : text;
        }
    }
}
