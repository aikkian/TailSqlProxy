using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Rules;

/// <summary>
/// Blocks SSMS IntelliSense, Object Explorer, and general metadata discovery queries.
/// Covers system catalog views, metadata stored procedures, DMVs, SERVERPROPERTY,
/// and SSMS-specific query patterns. Supports allowlisting and app-name-based blocking.
/// </summary>
public class SsmsMetadataRule : IQueryRule
{
    private readonly ILogger<SsmsMetadataRule> _logger;
    private readonly HashSet<string> _blockedProcedures;
    private readonly Regex[] _blockedPatterns;
    private readonly Regex[] _allowedPatterns;
    private readonly HashSet<string>? _blockedAppNames;
    private readonly bool _blockServerProperties;
    private readonly bool _blockDmvs;
    private readonly bool _blockSetStatements;

    public string Name => "SsmsMetadata";
    public bool IsEnabled { get; }

    // Metadata stored procedures called by SSMS IntelliSense and Object Explorer
    private static readonly string[] DefaultBlockedProcedures =
    [
        // IntelliSense procedures
        "sp_helpdb",
        "sp_helplogins",
        "sp_helptext",
        "sp_help",
        "sp_helpindex",
        "sp_helpsort",
        "sp_helprotect",
        "sp_helpconstraint",
        "sp_helpdevice",
        "sp_helplanguage",
        "sp_helpserver",
        "sp_helpextendedproc",

        // Result set metadata (IntelliSense + Query Editor)
        "sp_describe_undeclared_parameters",
        "sp_describe_first_result_set",
        "sp_describe_parameter_encryption",

        // Column/table metadata (IntelliSense autocomplete)
        "sp_columns",
        "sp_columns_100",
        "sp_columns_100_rowset",
        "sp_tables",
        "sp_fkeys",
        "sp_pkeys",
        "sp_statistics",
        "sp_sproc_columns",
        "sp_stored_procedures",
        "sp_table_privileges",
        "sp_column_privileges",
        "sp_special_columns",
        "sp_oledb_ro_usrname",

        // Database enumeration
        "sp_databases",
        "sp_catalogs",
        "sp_server_info",
        "sp_datatype_info",
        "sp_datatype_info_100",

        // Security/user metadata (Object Explorer Security node)
        "sp_helpuser",
        "sp_helprole",
        "sp_helprolemember",
        "sp_helpsrvrolemember",
        "sp_helpdbfixedrole",
        "sp_helpsrvrole",
        "sp_helplinkedsrvlogin",
    ];

    // System catalog views and DMVs queried by SSMS
    private static readonly string[] DefaultBlockedSystemViewPatterns =
    [
        // Core catalog views (IntelliSense cache population)
        @"\bsys\.databases\b",
        @"\bsys\.objects\b",
        @"\bsys\.tables\b",
        @"\bsys\.columns\b",
        @"\bsys\.all_objects\b",
        @"\bsys\.all_columns\b",
        @"\bsys\.schemas\b",
        @"\bsys\.types\b",
        @"\bsys\.systypes\b",
        @"\bsys\.synonyms\b",
        @"\bsys\.sql_modules\b",

        // Index metadata (Object Explorer)
        @"\bsys\.indexes\b",
        @"\bsys\.index_columns\b",

        // Key/constraint metadata (Object Explorer)
        @"\bsys\.foreign_keys\b",
        @"\bsys\.foreign_key_columns\b",
        @"\bsys\.key_constraints\b",
        @"\bsys\.check_constraints\b",
        @"\bsys\.default_constraints\b",

        // Object metadata (Object Explorer)
        @"\bsys\.views\b",
        @"\bsys\.procedures\b",
        @"\bsys\.parameters\b",
        @"\bsys\.triggers\b",
        @"\bsys\.computed_columns\b",
        @"\bsys\.identity_columns\b",
        @"\bsys\.sequences\b",
        @"\bsys\.partition_schemes\b",
        @"\bsys\.partition_functions\b",
        @"\bsys\.filegroups\b",
        @"\bsys\.database_files\b",

        // Security catalog views (Object Explorer Security node)
        @"\bsys\.server_principals\b",
        @"\bsys\.database_principals\b",
        @"\bsys\.database_permissions\b",
        @"\bsys\.server_permissions\b",
        @"\bsys\.database_role_members\b",
        @"\bsys\.server_role_members\b",

        // Legacy compatibility views
        @"\bsys\.syscolumns\b",
        @"\bsys\.sysobjects\b",
        @"\bsys\.sysindexes\b",
        @"\bsys\.sysusers\b",
        @"\bsys\.sysdatabases\b",
        @"\bsys\.syslogins\b",
        @"\bsys\.sysprocesses\b",
        @"\bsys\.syscomments\b",

        // Extended properties (Object Explorer descriptions)
        @"\bsys\.extended_properties\b",

        // Assembly/CLR metadata
        @"\bsys\.assemblies\b",
        @"\bsys\.assembly_modules\b",

        // Server configuration
        @"\bsys\.configurations\b",

        // INFORMATION_SCHEMA (all views)
        @"\bINFORMATION_SCHEMA\.\w+\b",
    ];

    // DMV patterns (blocked when BlockDmvs is true)
    private static readonly string[] DmvPatterns =
    [
        @"\bsys\.dm_exec_sessions\b",
        @"\bsys\.dm_exec_connections\b",
        @"\bsys\.dm_exec_requests\b",
        @"\bsys\.dm_exec_query_stats\b",
        @"\bsys\.dm_exec_query_plan\b",
        @"\bsys\.dm_exec_sql_text\b",
        @"\bsys\.dm_exec_cached_plans\b",
        @"\bsys\.dm_os_performance_counters\b",
        @"\bsys\.dm_os_wait_stats\b",
        @"\bsys\.dm_os_memory_clerks\b",
        @"\bsys\.dm_db_index_usage_stats\b",
        @"\bsys\.dm_db_index_physical_stats\b",
        @"\bsys\.dm_tran_active_transactions\b",
        @"\bsys\.dm_tran_locks\b",
    ];

    // Server property function patterns
    private static readonly string[] ServerPropertyPatterns =
    [
        @"(?i)\bSERVERPROPERTY\s*\(",
        @"(?i)@@VERSION\b",
        @"(?i)@@SERVERNAME\b",
        @"(?i)@@SERVICENAME\b",
        @"(?i)@@SPID\b",
        @"(?i)\bxp_msver\b",
    ];

    // SSMS connection-init SET statement patterns
    private static readonly string[] SetStatementPatterns =
    [
        @"(?i)^\s*SET\s+NOCOUNT\s+ON",
        @"(?i)^\s*SET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+READ\s+UNCOMMITTED",
        @"(?i)^\s*SET\s+LOCK_TIMEOUT\b",
        @"(?i)^\s*SET\s+TEXTSIZE\b",
        @"(?i)^\s*SET\s+ROWCOUNT\b",
    ];

    public SsmsMetadataRule(IOptions<RuleOptions> options, ILogger<SsmsMetadataRule> logger)
    {
        _logger = logger;
        var ssmsOptions = options.Value.SsmsMetadata;
        IsEnabled = ssmsOptions?.Enabled ?? true;

        _blockServerProperties = ssmsOptions?.BlockServerProperties ?? false;
        _blockDmvs = ssmsOptions?.BlockDmvs ?? false;
        _blockSetStatements = ssmsOptions?.BlockSetStatements ?? false;

        // Blocked app names (detect SSMS by Login7 AppName)
        _blockedAppNames = ssmsOptions?.BlockedAppNames is { Length: > 0 }
            ? new HashSet<string>(ssmsOptions.BlockedAppNames, StringComparer.OrdinalIgnoreCase)
            : null;

        // Build blocked procedures set
        var procs = ssmsOptions?.BlockedProcedures ?? DefaultBlockedProcedures;
        _blockedProcedures = new HashSet<string>(procs, StringComparer.OrdinalIgnoreCase);

        // Build blocked SQL patterns
        var allPatterns = new List<string>();

        var viewPatterns = ssmsOptions?.BlockedSystemViews?
            .Select(v => $@"\b{Regex.Escape(v)}\b")
            .ToArray();

        var schemaPatterns = ssmsOptions?.BlockedSchemas?
            .Select(s => $@"\b{Regex.Escape(s)}\.\w+\b")
            .ToArray();

        if (viewPatterns != null)
            allPatterns.AddRange(viewPatterns);
        else
            allPatterns.AddRange(DefaultBlockedSystemViewPatterns);

        if (schemaPatterns != null)
            allPatterns.AddRange(schemaPatterns);

        // Add DMV patterns if enabled
        if (_blockDmvs)
            allPatterns.AddRange(DmvPatterns);

        // Add server property patterns if enabled
        if (_blockServerProperties)
            allPatterns.AddRange(ServerPropertyPatterns);

        // Add SET statement patterns if enabled
        if (_blockSetStatements)
            allPatterns.AddRange(SetStatementPatterns);

        _blockedPatterns = allPatterns
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
            .ToArray();

        // Build allowed patterns
        _allowedPatterns = (ssmsOptions?.AllowedPatterns ?? [])
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
            .ToArray();
    }

    public RuleResult Evaluate(QueryContext context)
    {
        if (!IsEnabled)
            return RuleResult.Allow;

        // App-name-based blocking: if configured, only block queries from specific apps
        if (_blockedAppNames != null)
        {
            if (context.AppName == null || !_blockedAppNames.Contains(context.AppName))
                return RuleResult.Allow;
        }

        // Check RPC procedure name
        if (context.IsRpc && context.ProcedureName != null)
        {
            if (_blockedProcedures.Contains(context.ProcedureName))
                return RuleResult.Block($"Blocked metadata procedure: {context.ProcedureName}");
        }

        // Check SQL text against blocked patterns
        if (!string.IsNullOrWhiteSpace(context.SqlText))
        {
            // Allowlist takes priority
            foreach (var pattern in _allowedPatterns)
            {
                try
                {
                    if (pattern.IsMatch(context.SqlText))
                        return RuleResult.Allow;
                }
                catch (RegexMatchTimeoutException) { }
            }

            foreach (var pattern in _blockedPatterns)
            {
                try
                {
                    if (pattern.IsMatch(context.SqlText))
                        return RuleResult.Block($"Blocked metadata query matching pattern: {pattern}");
                }
                catch (RegexMatchTimeoutException)
                {
                    _logger.LogWarning("Regex timeout evaluating SSMS metadata pattern — blocking as precaution");
                    return RuleResult.Block("Blocked metadata query: pattern evaluation timeout");
                }
            }
        }

        return RuleResult.Allow;
    }
}
