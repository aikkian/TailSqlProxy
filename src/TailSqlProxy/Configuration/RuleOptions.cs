namespace TailSqlProxy.Configuration;

public class RuleOptions
{
    public UnboundedSelectOptions? UnboundedSelect { get; set; }
    public UnboundedDeleteOptions? UnboundedDelete { get; set; }
    public SsmsMetadataOptions? SsmsMetadata { get; set; }
    public SqlInjectionOptions? SqlInjection { get; set; }
    public AccessControlOptions? AccessControl { get; set; }

    /// <summary>
    /// Users in this list bypass all query blocking rules.
    /// Matched case-insensitively against the Login7 username.
    /// Example: ["admin_user", "deploy_svc"]
    /// </summary>
    public string[] BypassUsers { get; set; } = [];

    /// <summary>
    /// Application names in this list bypass all query blocking rules.
    /// Matched case-insensitively against the Login7 app name.
    /// Example: ["MyDeployTool", "DataMigrator"]
    /// </summary>
    public string[] BypassAppNames { get; set; } = [];

    /// <summary>
    /// Client IPs in this list bypass all query blocking rules.
    /// Example: ["10.0.0.50", "192.168.1.100"]
    /// </summary>
    public string[] BypassClientIps { get; set; } = [];
}

public class UnboundedSelectOptions
{
    public bool Enabled { get; set; } = true;
}

public class UnboundedDeleteOptions
{
    public bool Enabled { get; set; } = true;
}

public class SqlInjectionOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// When true, SQL with parse errors AND suspicious characteristics is blocked.
    /// Legitimate application SQL rarely has parse errors; injected payloads often do.
    /// Default: false (conservative — only block on definitive patterns).
    /// </summary>
    public bool BlockOnParseErrors { get; set; }

    /// <summary>
    /// Additional regex patterns to detect custom injection signatures.
    /// These are checked alongside the built-in patterns.
    /// </summary>
    public string[]? CustomPatterns { get; set; }
}

public class SsmsMetadataOptions
{
    public bool Enabled { get; set; } = true;
    public string[]? BlockedProcedures { get; set; }
    public string[]? BlockedSystemViews { get; set; }
    public string[]? BlockedSchemas { get; set; }
    public string[]? AllowedPatterns { get; set; }

    /// <summary>
    /// Block queries only from these app names (case-insensitive).
    /// If empty/null, metadata is blocked from all apps.
    /// Typical: ["Microsoft SQL Server Management Studio", "SQLServerCEIP", "azdata"]
    /// </summary>
    public string[]? BlockedAppNames { get; set; }

    /// <summary>Block SERVERPROPERTY(), @@VERSION, @@SERVERNAME, etc.</summary>
    public bool BlockServerProperties { get; set; }

    /// <summary>Block DMVs: sys.dm_exec_*, sys.dm_os_*, sys.dm_db_*, sys.dm_tran_*.</summary>
    public bool BlockDmvs { get; set; }

    /// <summary>Block SSMS connection-init SET statements (SET NOCOUNT ON, SET TEXTSIZE, etc.).</summary>
    public bool BlockSetStatements { get; set; }
}

public class AccessControlOptions
{
    public bool Enabled { get; set; }
    public AccessControlPolicy[]? Policies { get; set; }
}

/// <summary>
/// An access control policy defining who can do what on which objects.
/// Policies are evaluated in priority order (highest first).
/// </summary>
public class AccessControlPolicy
{
    /// <summary>Policy name for audit log display.</summary>
    public string? Name { get; set; }

    /// <summary>Higher priority policies are evaluated first.</summary>
    public int Priority { get; set; }

    /// <summary>Deny or Allow this access.</summary>
    public PolicyAction Action { get; set; } = PolicyAction.Deny;

    // --- Subject (WHO) ---

    /// <summary>Users this policy applies to. Null = all users.</summary>
    public string[]? Users { get; set; }

    /// <summary>App names this policy applies to. Null = all apps.</summary>
    public string[]? AppNames { get; set; }

    /// <summary>Client IPs this policy applies to. Null = all IPs.</summary>
    public string[]? ClientIps { get; set; }

    // --- Object (WHAT) ---

    /// <summary>Database name. Null = all databases.</summary>
    public string? Database { get; set; }

    /// <summary>Regex pattern for table/view names (e.g. "^dbo\\.Salary$", ".*_sensitive").</summary>
    public string? ObjectPattern { get; set; }

    /// <summary>Specific columns. Null = all columns on matched objects.</summary>
    public string[]? Columns { get; set; }

    // --- Operation (HOW) ---

    /// <summary>SQL operations this policy applies to. Null = all operations.</summary>
    public SqlOperation[]? Operations { get; set; }
}

public enum PolicyAction
{
    Deny,
    Allow,
}

public enum SqlOperation
{
    Select,
    Insert,
    Update,
    Delete,
}
