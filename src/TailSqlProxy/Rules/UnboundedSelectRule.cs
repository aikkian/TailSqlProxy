using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.SqlServer.TransactSql.ScriptDom;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

public class UnboundedSelectRule : IQueryRule
{
    private readonly ILogger<UnboundedSelectRule> _logger;

    public string Name => "UnboundedSelect";
    public bool IsEnabled { get; }

    public UnboundedSelectRule(IOptions<RuleOptions> options, ILogger<UnboundedSelectRule> logger)
    {
        _logger = logger;
        IsEnabled = options.Value.UnboundedSelect?.Enabled ?? true;
    }

    public RuleResult Evaluate(QueryContext context)
    {
        if (!IsEnabled)
            return RuleResult.Allow;

        if (string.IsNullOrWhiteSpace(context.SqlText))
            return RuleResult.Allow;

        // Only check sp_executesql SQL text if it's an RPC
        if (context.IsRpc && !string.Equals(context.ProcedureName, "sp_executesql", StringComparison.OrdinalIgnoreCase))
            return RuleResult.Allow;

        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(context.SqlText);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return RuleResult.Allow; // Let SQL Server handle parse errors

        var visitor = new UnboundedSelectVisitor();
        fragment.Accept(visitor);

        if (visitor.HasViolation)
            return RuleResult.Block($"SELECT without TOP or WHERE clause is not allowed. Fragment: {visitor.OffendingFragment}");

        return RuleResult.Allow;
    }

    private class UnboundedSelectVisitor : TSqlFragmentVisitor
    {
        public bool HasViolation { get; private set; }
        public string? OffendingFragment { get; private set; }

        public override void Visit(QuerySpecification node)
        {
            if (HasViolation)
                return;

            // Only check if there's a FROM clause (skip SELECT 1, SELECT GETDATE(), etc.)
            if (node.FromClause == null)
                return;

            // Check if this is SELECT * (all columns)
            bool hasStarColumn = node.SelectElements.Any(e => e is SelectStarExpression);

            if (!hasStarColumn)
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
