using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.SqlServer.TransactSql.ScriptDom;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

/// <summary>
/// Granular access control rule that enforces table-level, column-level,
/// and operation-level policies. Policies define which users/apps can
/// perform which SQL operations on which database objects.
/// </summary>
public class AccessControlRule : IQueryRule
{
    private readonly ILogger<AccessControlRule> _logger;
    private readonly List<CompiledPolicy> _policies;

    public string Name => "AccessControl";
    public bool IsEnabled { get; }

    public AccessControlRule(IOptions<RuleOptions> options, ILogger<AccessControlRule> logger)
    {
        _logger = logger;
        var acOptions = options.Value.AccessControl ?? new AccessControlOptions();
        IsEnabled = acOptions.Enabled;
        _policies = CompilePolicies(acOptions.Policies ?? []);
    }

    public RuleResult Evaluate(QueryContext context)
    {
        if (!IsEnabled)
            return RuleResult.Allow;

        if (string.IsNullOrWhiteSpace(context.SqlText))
            return RuleResult.Allow;

        // Only evaluate SQL Batch and sp_executesql RPC calls
        if (context.IsRpc && !string.Equals(context.ProcedureName, "sp_executesql", StringComparison.OrdinalIgnoreCase))
            return RuleResult.Allow;

        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(context.SqlText);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return RuleResult.Allow; // Let SQL Server handle parse errors

        var visitor = new AccessControlVisitor();
        fragment.Accept(visitor);

        // Check each accessed object against policies
        foreach (var access in visitor.Accesses)
        {
            foreach (var policy in _policies)
            {
                if (!policy.Matches(context, access))
                    continue;

                if (policy.Action == PolicyAction.Deny)
                {
                    var target = access.Columns.Count > 0
                        ? $"{access.ObjectName} (columns: {string.Join(", ", access.Columns)})"
                        : access.ObjectName;

                    return RuleResult.Block(
                        $"Access denied by policy [{policy.Name}]: {access.Operation} on {target} " +
                        $"is not allowed for user [{context.Username}]");
                }
            }
        }

        return RuleResult.Allow;
    }

    private static List<CompiledPolicy> CompilePolicies(AccessControlPolicy[] policies)
    {
        return policies
            .Select(p => new CompiledPolicy(p))
            .OrderByDescending(p => p.Priority)
            .ToList();
    }

    /// <summary>
    /// Compiled version of an access control policy with pre-built matchers.
    /// </summary>
    private sealed class CompiledPolicy
    {
        public string Name { get; }
        public PolicyAction Action { get; }
        public int Priority { get; }

        private readonly HashSet<string>? _users;
        private readonly HashSet<string>? _appNames;
        private readonly HashSet<string>? _clientIps;
        private readonly HashSet<SqlOperation> _operations;
        private readonly Regex? _objectPattern;
        private readonly HashSet<string>? _columns;
        private readonly string? _database;

        public CompiledPolicy(AccessControlPolicy policy)
        {
            Name = policy.Name ?? "Unnamed";
            Action = policy.Action;
            Priority = policy.Priority;

            _users = policy.Users is { Length: > 0 }
                ? new HashSet<string>(policy.Users, StringComparer.OrdinalIgnoreCase) : null;
            _appNames = policy.AppNames is { Length: > 0 }
                ? new HashSet<string>(policy.AppNames, StringComparer.OrdinalIgnoreCase) : null;
            _clientIps = policy.ClientIps is { Length: > 0 }
                ? new HashSet<string>(policy.ClientIps, StringComparer.Ordinal) : null;

            _operations = new HashSet<SqlOperation>(policy.Operations ?? [SqlOperation.Select, SqlOperation.Insert, SqlOperation.Update, SqlOperation.Delete]);

            _objectPattern = !string.IsNullOrWhiteSpace(policy.ObjectPattern)
                ? new Regex(policy.ObjectPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100))
                : null;

            _columns = policy.Columns is { Length: > 0 }
                ? new HashSet<string>(policy.Columns, StringComparer.OrdinalIgnoreCase) : null;

            _database = policy.Database;
        }

        public bool Matches(QueryContext context, ObjectAccess access)
        {
            // Check subject (who): user, app, IP — all must match if specified
            if (_users != null && (context.Username == null || !_users.Contains(context.Username)))
                return false;
            if (_appNames != null && (context.AppName == null || !_appNames.Contains(context.AppName)))
                return false;
            if (_clientIps != null && (context.ClientIp == null || !_clientIps.Contains(context.ClientIp)))
                return false;

            // Check database
            if (_database != null && !string.Equals(_database, context.Database, StringComparison.OrdinalIgnoreCase))
                return false;

            // Check operation
            if (!_operations.Contains(access.Operation))
                return false;

            // Check object name
            if (_objectPattern != null)
            {
                try
                {
                    if (!_objectPattern.IsMatch(access.ObjectName))
                        return false;
                }
                catch (RegexMatchTimeoutException)
                {
                    return false;
                }
            }

            // Check columns — if policy specifies columns, at least one accessed column must match
            if (_columns != null && access.Columns.Count > 0)
            {
                if (!access.Columns.Any(c => _columns.Contains(c)))
                    return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Represents an access to a database object detected in the SQL statement.
    /// </summary>
    internal sealed class ObjectAccess
    {
        public required string ObjectName { get; init; }
        public required SqlOperation Operation { get; init; }
        public List<string> Columns { get; init; } = [];
    }

    /// <summary>
    /// AST visitor that extracts all table/view accesses and their operations.
    /// </summary>
    private sealed class AccessControlVisitor : TSqlFragmentVisitor
    {
        public List<ObjectAccess> Accesses { get; } = [];

        public override void Visit(SelectStatement node)
        {
            if (node.QueryExpression is QuerySpecification querySpec)
            {
                var tables = ExtractTableNames(querySpec.FromClause);
                var columns = ExtractSelectColumns(querySpec);

                foreach (var table in tables)
                {
                    Accesses.Add(new ObjectAccess
                    {
                        ObjectName = table,
                        Operation = SqlOperation.Select,
                        Columns = columns,
                    });
                }
            }

            base.Visit(node);
        }

        public override void Visit(InsertStatement node)
        {
            var target = ExtractTargetName(node.InsertSpecification.Target);
            if (target != null)
            {
                var columns = node.InsertSpecification.Columns
                    .Select(c => c.MultiPartIdentifier.Identifiers.Last().Value)
                    .ToList();

                Accesses.Add(new ObjectAccess
                {
                    ObjectName = target,
                    Operation = SqlOperation.Insert,
                    Columns = columns,
                });
            }
        }

        public override void Visit(UpdateStatement node)
        {
            var target = ExtractTargetName(node.UpdateSpecification.Target);
            if (target != null)
            {
                var columns = node.UpdateSpecification.SetClauses
                    .OfType<AssignmentSetClause>()
                    .Select(c => c.Column?.MultiPartIdentifier?.Identifiers.Last().Value)
                    .Where(c => c != null)
                    .Cast<string>()
                    .ToList();

                Accesses.Add(new ObjectAccess
                {
                    ObjectName = target,
                    Operation = SqlOperation.Update,
                    Columns = columns,
                });
            }
        }

        public override void Visit(DeleteStatement node)
        {
            var target = ExtractTargetName(node.DeleteSpecification.Target);
            if (target != null)
            {
                Accesses.Add(new ObjectAccess
                {
                    ObjectName = target,
                    Operation = SqlOperation.Delete,
                });
            }
        }

        private static string? ExtractTargetName(TableReference? target) => target switch
        {
            NamedTableReference named => GetFullTableName(named.SchemaObject),
            _ => null,
        };

        private static List<string> ExtractTableNames(FromClause? fromClause)
        {
            if (fromClause == null)
                return [];

            var tables = new List<string>();
            foreach (var tableRef in fromClause.TableReferences)
            {
                CollectTableNames(tableRef, tables);
            }
            return tables;
        }

        private static void CollectTableNames(TableReference tableRef, List<string> tables)
        {
            switch (tableRef)
            {
                case NamedTableReference named:
                    tables.Add(GetFullTableName(named.SchemaObject));
                    break;
                case JoinTableReference join:
                    CollectTableNames(join.FirstTableReference, tables);
                    CollectTableNames(join.SecondTableReference, tables);
                    break;
            }
        }

        private static List<string> ExtractSelectColumns(QuerySpecification querySpec)
        {
            var columns = new List<string>();
            foreach (var element in querySpec.SelectElements)
            {
                switch (element)
                {
                    case SelectStarExpression:
                        columns.Add("*");
                        break;
                    case SelectScalarExpression { ColumnName: not null } scalar:
                        columns.Add(scalar.ColumnName.Value);
                        break;
                    case SelectScalarExpression { Expression: ColumnReferenceExpression colRef }:
                        columns.Add(colRef.MultiPartIdentifier.Identifiers.Last().Value);
                        break;
                }
            }
            return columns;
        }

        private static string GetFullTableName(SchemaObjectName schemaObject)
        {
            var parts = schemaObject.Identifiers.Select(i => i.Value);
            return string.Join(".", parts);
        }
    }
}
