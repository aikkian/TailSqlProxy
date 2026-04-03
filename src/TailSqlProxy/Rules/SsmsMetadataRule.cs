using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

public class SsmsMetadataRule : IQueryRule
{
    private readonly ILogger<SsmsMetadataRule> _logger;
    private readonly HashSet<string> _blockedProcedures;
    private readonly Regex[] _blockedPatterns;
    private readonly Regex[] _allowedPatterns;

    public string Name => "SsmsMetadata";
    public bool IsEnabled { get; }

    private static readonly string[] DefaultBlockedProcedures =
    [
        "sp_helpdb",
        "sp_helplogins",
        "sp_describe_undeclared_parameters",
        "sp_describe_first_result_set",
        "sp_oledb_ro_usrname",
        "sp_help",
        "sp_columns",
        "sp_tables",
        "sp_fkeys",
        "sp_pkeys",
        "sp_statistics",
        "sp_sproc_columns",
        "sp_stored_procedures",
        "sp_table_privileges",
        "sp_column_privileges",
    ];

    private static readonly string[] DefaultBlockedSystemViewPatterns =
    [
        @"\bsys\.databases\b",
        @"\bsys\.objects\b",
        @"\bsys\.tables\b",
        @"\bsys\.columns\b",
        @"\bsys\.all_objects\b",
        @"\bsys\.all_columns\b",
        @"\bsys\.schemas\b",
        @"\bsys\.types\b",
        @"\bsys\.indexes\b",
        @"\bsys\.index_columns\b",
        @"\bsys\.foreign_keys\b",
        @"\bsys\.foreign_key_columns\b",
        @"\bsys\.key_constraints\b",
        @"\bsys\.views\b",
        @"\bsys\.procedures\b",
        @"\bsys\.parameters\b",
        @"\bsys\.sql_modules\b",
        @"\bsys\.syscolumns\b",
        @"\bsys\.sysobjects\b",
        @"\bINFORMATION_SCHEMA\.\w+\b",
    ];

    public SsmsMetadataRule(IOptions<RuleOptions> options, ILogger<SsmsMetadataRule> logger)
    {
        _logger = logger;
        var ssmsOptions = options.Value.SsmsMetadata;
        IsEnabled = ssmsOptions?.Enabled ?? true;

        // Build blocked procedures set
        var procs = ssmsOptions?.BlockedProcedures ?? DefaultBlockedProcedures;
        _blockedProcedures = new HashSet<string>(procs, StringComparer.OrdinalIgnoreCase);

        // Build blocked SQL patterns
        var viewPatterns = ssmsOptions?.BlockedSystemViews?
            .Select(v => $@"\b{Regex.Escape(v)}\b")
            .ToArray();

        var schemaPatterns = ssmsOptions?.BlockedSchemas?
            .Select(s => $@"\b{Regex.Escape(s)}\.\w+\b")
            .ToArray();

        var allPatterns = new List<string>();

        if (viewPatterns != null)
            allPatterns.AddRange(viewPatterns);
        else
            allPatterns.AddRange(DefaultBlockedSystemViewPatterns);

        if (schemaPatterns != null)
            allPatterns.AddRange(schemaPatterns);

        _blockedPatterns = allPatterns
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase))
            .ToArray();

        // Build allowed patterns
        _allowedPatterns = (ssmsOptions?.AllowedPatterns ?? [])
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase))
            .ToArray();
    }

    public RuleResult Evaluate(QueryContext context)
    {
        if (!IsEnabled)
            return RuleResult.Allow;

        // Check RPC procedure name
        if (context.IsRpc && context.ProcedureName != null)
        {
            if (_blockedProcedures.Contains(context.ProcedureName))
                return RuleResult.Block($"Blocked metadata procedure: {context.ProcedureName}");
        }

        // Check SQL text against blocked patterns
        if (!string.IsNullOrWhiteSpace(context.SqlText))
        {
            // First check if it matches an allowed pattern (allowlist takes priority)
            if (_allowedPatterns.Any(p => p.IsMatch(context.SqlText)))
                return RuleResult.Allow;

            foreach (var pattern in _blockedPatterns)
            {
                if (pattern.IsMatch(context.SqlText))
                    return RuleResult.Block($"Blocked metadata query matching pattern: {pattern}");
            }
        }

        return RuleResult.Allow;
    }
}
