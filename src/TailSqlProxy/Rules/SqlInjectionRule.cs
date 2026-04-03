using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.SqlServer.TransactSql.ScriptDom;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

public class SqlInjectionRule : IQueryRule
{
    private readonly ILogger<SqlInjectionRule> _logger;
    private readonly SqlInjectionOptions _injectionOptions;
    private readonly Regex[] _dangerousPatterns;

    public string Name => "SqlInjection";
    public bool IsEnabled { get; }

    // Dangerous system procedures that should never come from normal application traffic
    private static readonly HashSet<string> DangerousProcs = new(StringComparer.OrdinalIgnoreCase)
    {
        "xp_cmdshell",
        "xp_regread",
        "xp_regwrite",
        "xp_regdelete",
        "xp_servicecontrol",
        "xp_availablemedia",
        "xp_dirtree",
        "xp_fileexist",
        "xp_fixeddrives",
        "xp_subdirs",
        "sp_OACreate",
        "sp_OAMethod",
        "sp_OAGetProperty",
        "sp_OASetProperty",
        "sp_OADestroy",
        "sp_addlogin",
        "sp_addsrvrolemember",
        "sp_password",
        "sp_configure",
        "sp_makewebtask",
    };

    // Regex patterns for SQL injection detection (compiled for performance).
    // These catch obfuscated attacks that bypass AST parsing.
    private static readonly (string Pattern, string Description)[] DefaultInjectionPatterns =
    [
        // Tautology attacks
        (@"(?i)\bOR\s+1\s*=\s*1\b", "Tautology: OR 1=1"),
        (@"(?i)\bOR\s+'[^']*'\s*=\s*'[^']*'", "Tautology: OR ''=''"),
        (@"(?i)\bOR\s+""[^""]*""\s*=\s*""[^""]*""", "Tautology: OR \"\"=\"\""),
        (@"(?i)\bOR\s+\d+\s*=\s*\d+\b", "Tautology: OR N=N"),
        (@"(?i)\bOR\s+true\b", "Tautology: OR true"),

        // Time-based blind injection (require preceding statement separator for WAITFOR)
        (@"(?i);\s*WAITFOR\s+DELAY\s+'", "Time-based injection: WAITFOR DELAY after statement"),
        (@"(?i);\s*WAITFOR\s+TIME\s+'", "Time-based injection: WAITFOR TIME after statement"),
        (@"(?i)\bBENCHMARK\s*\(", "Time-based injection: BENCHMARK"),
        (@"(?i)\bSLEEP\s*\(", "Time-based injection: SLEEP()"),
        (@"(?i)\bpg_sleep\s*\(", "Time-based injection: pg_sleep()"),

        // Stacked query injection — dangerous commands after semicolons
        (@"(?i);\s*DROP\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE|FUNCTION)\b", "Stacked injection: DROP"),
        (@"(?i);\s*ALTER\s+(TABLE|DATABASE|LOGIN|ROLE|USER)\b", "Stacked injection: ALTER"),
        (@"(?i);\s*CREATE\s+(LOGIN|USER)\b", "Stacked injection: CREATE LOGIN/USER"),
        (@"(?i);\s*EXEC(UTE)?\s+xp_", "Stacked injection: EXEC xp_"),
        (@"(?i);\s*EXEC(UTE)?\s+sp_OA", "Stacked injection: EXEC sp_OA"),
        (@"(?i);\s*SHUTDOWN\b", "Stacked injection: SHUTDOWN"),
        (@"(?i);\s*TRUNCATE\s+TABLE\b", "Stacked injection: TRUNCATE TABLE"),

        // UNION-based injection
        (@"(?i)\bUNION\s+(ALL\s+)?SELECT\s+NULL\b", "UNION injection: SELECT NULL"),
        (@"(?i)\bUNION\s+(ALL\s+)?SELECT\s+\d+\s*,", "UNION injection: SELECT numeric columns"),
        (@"(?i)\bUNION\s+(ALL\s+)?SELECT\s+(CHAR|CHR)\s*\(", "UNION injection: SELECT CHAR()"),

        // Comment-based evasion (inline comments used to break up keywords)
        (@"(?i)/\*.*?\*/\s*(UNION|SELECT|DROP|DELETE|INSERT|UPDATE|ALTER|EXEC)\b", "Comment evasion: inline comment before keyword"),
        (@"(?i)(UNION|SELECT|DROP|DELETE|INSERT|UPDATE|ALTER|EXEC)\s*/\*.*?\*/", "Comment evasion: inline comment after keyword"),

        // Hex/CHAR encoding attacks
        (@"(?i)\bCHAR\s*\(\s*0x", "Hex encoding attack: CHAR(0x...)"),
        (@"(?i)0x[0-9a-fA-F]{8,}", "Hex string literal (potential encoded payload)"),

        // Information schema probing (common in automated injection tools)
        (@"(?i)\bSELECT\b.*\bFROM\b.*\bsysobjects\b", "Schema probing: sysobjects"),
        (@"(?i)\bSELECT\b.*\bFROM\b.*\bsyscolumns\b", "Schema probing: syscolumns"),
        (@"(?i)@@version\b", "Information probing: @@version"),
        (@"(?i)\buser_name\s*\(\s*\)", "Information probing: user_name()"),
        (@"(?i)\bsystem_user\b", "Information probing: system_user"),

        // Error-based injection
        (@"(?i)\bCONVERT\s*\(\s*int\s*,\s*@@", "Error-based injection: CONVERT(int, @@...)"),
        (@"(?i)\bCAST\s*\(\s*@@\w+\s+AS\s+", "Error-based injection: CAST(@@var AS ...)"),

        // Dangerous system commands
        (@"(?i)\bOPENROWSET\s*\(", "Data exfiltration: OPENROWSET"),
        (@"(?i)\bOPENDATASOURCE\s*\(", "Data exfiltration: OPENDATASOURCE"),
        (@"(?i)\bBULK\s+INSERT\b", "File access: BULK INSERT"),
    ];

    public SqlInjectionRule(IOptions<RuleOptions> options, ILogger<SqlInjectionRule> logger)
    {
        _logger = logger;
        _injectionOptions = options.Value.SqlInjection ?? new SqlInjectionOptions();
        IsEnabled = _injectionOptions.Enabled;

        // Build regex patterns: defaults + any custom patterns from config
        var patterns = new List<(string Pattern, string Description)>(DefaultInjectionPatterns);

        if (_injectionOptions.CustomPatterns is { Length: > 0 })
        {
            foreach (var custom in _injectionOptions.CustomPatterns)
            {
                patterns.Add((custom, $"Custom pattern: {custom}"));
            }
        }

        _dangerousPatterns = patterns
            .Select(p => new Regex(p.Pattern, RegexOptions.Compiled | RegexOptions.Singleline, TimeSpan.FromMilliseconds(100)))
            .ToArray();
    }

    public RuleResult Evaluate(QueryContext context)
    {
        if (!IsEnabled)
            return RuleResult.Allow;

        // Check RPC for dangerous procedure calls
        if (context.IsRpc && context.ProcedureName != null)
        {
            if (DangerousProcs.Contains(context.ProcedureName))
                return RuleResult.Block($"SQL injection: dangerous procedure call [{context.ProcedureName}]");
        }

        if (string.IsNullOrWhiteSpace(context.SqlText))
            return RuleResult.Allow;

        // 1. Regex-based detection (catches obfuscated attacks)
        var regexResult = CheckRegexPatterns(context.SqlText);
        if (regexResult.IsBlocked)
            return regexResult;

        // 2. AST-based detection (catches structural injection patterns)
        var astResult = CheckAstPatterns(context.SqlText);
        if (astResult.IsBlocked)
            return astResult;

        return RuleResult.Allow;
    }

    private RuleResult CheckRegexPatterns(string sql)
    {
        for (int i = 0; i < _dangerousPatterns.Length; i++)
        {
            try
            {
                if (_dangerousPatterns[i].IsMatch(sql))
                {
                    var description = i < DefaultInjectionPatterns.Length
                        ? DefaultInjectionPatterns[i].Description
                        : $"Custom pattern match";

                    return RuleResult.Block($"SQL injection detected: {description}");
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Pattern took too long — possible ReDoS attempt, block defensively
                _logger.LogWarning("Regex timeout evaluating SQL injection pattern {Index} — blocking as precaution", i);
                return RuleResult.Block("SQL injection detected: pattern evaluation timeout (possible evasion)");
            }
        }

        return RuleResult.Allow;
    }

    private RuleResult CheckAstPatterns(string sql)
    {
        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sql);
        var fragment = parser.Parse(reader, out var errors);

        // If the SQL has parse errors, check for suspicious characteristics
        // Legitimate application SQL rarely has parse errors
        if (errors.Count > 0 && _injectionOptions.BlockOnParseErrors)
        {
            // Only block if the SQL also matches suspicious characteristics
            if (HasSuspiciousCharacteristics(sql))
                return RuleResult.Block($"SQL injection suspected: malformed SQL with suspicious content ({errors.Count} parse errors)");

            return RuleResult.Allow;
        }

        if (errors.Count > 0)
            return RuleResult.Allow;

        var visitor = new SqlInjectionVisitor();
        fragment.Accept(visitor);

        if (visitor.HasViolation)
            return RuleResult.Block($"SQL injection detected: {visitor.Reason}");

        return RuleResult.Allow;
    }

    /// <summary>
    /// Checks for characteristics common in SQL injection but rare in normal SQL.
    /// Used as a secondary signal when parse errors are present.
    /// </summary>
    private static bool HasSuspiciousCharacteristics(string sql)
    {
        var upper = sql.ToUpperInvariant();

        // Multiple statement terminators with dangerous keywords
        if (upper.Contains(';') && (
            upper.Contains("DROP ") ||
            upper.Contains("SHUTDOWN") ||
            upper.Contains("XP_CMDSHELL") ||
            upper.Contains("SP_OA")))
            return true;

        // Comment sequences mixed with keywords (evasion technique)
        if (upper.Contains("/*") && upper.Contains("*/") && (
            upper.Contains("UNION") ||
            upper.Contains("SELECT") ||
            upper.Contains("DROP")))
            return true;

        return false;
    }

    /// <summary>
    /// AST visitor that detects structural SQL injection patterns:
    /// - UNION SELECT with mismatched context (injection probe)
    /// - Tautology WHERE clauses (OR 1=1)
    /// - Stacked dangerous statements (DROP, SHUTDOWN, xp_ calls)
    /// - WAITFOR DELAY (time-based blind injection)
    /// </summary>
    private class SqlInjectionVisitor : TSqlFragmentVisitor
    {
        public bool HasViolation { get; private set; }
        public string? Reason { get; private set; }

        private int _statementCount;
        private bool _hasDropOrAlter;

        public override void Visit(TSqlBatch node)
        {
            _statementCount = node.Statements.Count;

            // Check for stacked dangerous statements
            foreach (var stmt in node.Statements)
            {
                if (stmt is DropTableStatement or DropDatabaseStatement
                    or DropProcedureStatement or DropFunctionStatement
                    or DropViewStatement or DropIndexStatement)
                {
                    _hasDropOrAlter = true;
                }

                if (stmt is TruncateTableStatement)
                {
                    _hasDropOrAlter = true;
                }

                if (stmt is ShutdownStatement)
                {
                    HasViolation = true;
                    Reason = "SHUTDOWN statement detected";
                    return;
                }
            }

            // Stacked query with DROP/ALTER alongside SELECT is suspicious
            if (_statementCount > 1 && _hasDropOrAlter)
            {
                HasViolation = true;
                Reason = "stacked query containing destructive statement (DROP/TRUNCATE)";
                return;
            }

            base.Visit(node);
        }

        public override void Visit(ExecuteStatement node)
        {
            if (HasViolation) return;

            // Check if EXEC calls a dangerous procedure
            if (node.ExecuteSpecification?.ExecutableEntity is ExecutableProcedureReference procRef)
            {
                var procName = procRef.ProcedureReference?.ProcedureReference?.Name?.BaseIdentifier?.Value;
                if (procName != null && DangerousProcs.Contains(procName))
                {
                    HasViolation = true;
                    Reason = $"dangerous procedure call: {procName}";
                    return;
                }
            }
        }

        public override void Visit(WaitForStatement node)
        {
            if (HasViolation) return;

            // WAITFOR DELAY in non-trivial batches is suspicious (time-based blind injection)
            if (_statementCount > 1 && node.WaitForOption == WaitForOption.Delay)
            {
                HasViolation = true;
                Reason = "WAITFOR DELAY in multi-statement batch (time-based blind injection)";
            }
        }

        public override void Visit(BooleanComparisonExpression node)
        {
            if (HasViolation) return;

            // Detect tautologies: literal = literal (e.g., 1=1, 'a'='a')
            if (node.ComparisonType == BooleanComparisonType.Equals
                && IsLiteral(node.FirstExpression)
                && IsLiteral(node.SecondExpression))
            {
                // Check if both sides are the same value (true tautology)
                var left = GetLiteralValue(node.FirstExpression);
                var right = GetLiteralValue(node.SecondExpression);

                if (left != null && right != null && string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
                {
                    HasViolation = true;
                    Reason = $"tautology detected: {left}={right}";
                }
            }
        }

        public override void Visit(BinaryQueryExpression node)
        {
            if (HasViolation) return;

            if (node.BinaryQueryExpressionType is not BinaryQueryExpressionType.Union)
                return;

            // Check if the second part of the UNION is all literals/NULLs (injection probe)
            if (node.SecondQueryExpression is QuerySpecification querySpec)
            {
                var allLiteralsOrNull = querySpec.SelectElements.Count > 0
                    && querySpec.SelectElements.All(e =>
                        e is SelectScalarExpression sse
                        && (IsLiteral(sse.Expression) || sse.Expression is NullLiteral));

                if (allLiteralsOrNull && querySpec.FromClause == null)
                {
                    HasViolation = true;
                    Reason = "UNION SELECT with all literal/NULL columns (injection probe)";
                }
            }
        }

        private static bool IsLiteral(ScalarExpression expr) =>
            expr is IntegerLiteral or StringLiteral or NumericLiteral or NullLiteral;

        private static string? GetLiteralValue(ScalarExpression expr) => expr switch
        {
            IntegerLiteral i => i.Value,
            StringLiteral s => s.Value,
            NumericLiteral n => n.Value,
            _ => null,
        };
    }
}
