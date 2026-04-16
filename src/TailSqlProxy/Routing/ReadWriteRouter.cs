using Microsoft.Extensions.Logging;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Routing;

/// <summary>
/// Routes queries to either the primary (read-write) or read-only replica connection
/// based on query classification, transaction state, and app-name rules.
/// </summary>
public sealed class ReadWriteRouter
{
    private readonly ReadWriteSplitOptions _options;
    private readonly TransactionTracker _transactionTracker = new();
    private readonly ILogger _logger;

    private readonly HashSet<string> _alwaysPrimaryApps;
    private readonly HashSet<string> _alwaysReadOnlyApps;

    // Track whether the read-only connection has been used in this session
    // (lazy initialization — only connect when actually needed)
    private bool _readOnlyConnectionUsed;

    public ReadWriteRouter(ReadWriteSplitOptions options, ILogger logger)
    {
        _options = options;
        _logger = logger;
        _alwaysPrimaryApps = new HashSet<string>(
            options.AlwaysPrimaryAppNames ?? [], StringComparer.OrdinalIgnoreCase);
        _alwaysReadOnlyApps = new HashSet<string>(
            options.AlwaysReadOnlyAppNames ?? [], StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>True if the read/write split feature is enabled.</summary>
    public bool IsEnabled => _options.Enabled;

    /// <summary>True if the read-only connection has been used at least once this session.</summary>
    public bool ReadOnlyConnectionUsed => _readOnlyConnectionUsed;

    /// <summary>Current transaction state tracker.</summary>
    public TransactionTracker TransactionTracker => _transactionTracker;

    /// <summary>
    /// Determines which connection a SQL batch should be routed to.
    /// Also updates the transaction tracker.
    /// </summary>
    public RouteTarget RouteSqlBatch(string? sqlText, string? appName)
    {
        if (!_options.Enabled)
            return RouteTarget.Primary;

        // App-name overrides
        if (appName != null && _alwaysPrimaryApps.Contains(appName))
            return RouteTarget.Primary;

        if (appName != null && _alwaysReadOnlyApps.Contains(appName))
        {
            _readOnlyConnectionUsed = true;
            return RouteTarget.ReadOnly;
        }

        // Update transaction tracking
        _transactionTracker.TrackSqlBatch(sqlText);

        // Active transaction — must go to primary
        if (_transactionTracker.InTransaction)
        {
            _logger.LogDebug("Routing to primary: active transaction (depth={Depth})",
                _transactionTracker.Depth);
            return RouteTarget.Primary;
        }

        // Classify the query
        if (QueryClassifier.IsReadOnly(sqlText))
        {
            _readOnlyConnectionUsed = true;
            _logger.LogDebug("Routing to read-only replica: read-only query");
            return RouteTarget.ReadOnly;
        }

        _logger.LogDebug("Routing to primary: write operation detected");
        return RouteTarget.Primary;
    }

    /// <summary>
    /// Determines routing for an RPC request.
    /// sp_executesql with a read-only SQL payload goes to read-only;
    /// all other RPCs go to primary (we can't know if a stored proc writes).
    /// </summary>
    public RouteTarget RouteRpc(string? procName, string? sqlText, string? appName)
    {
        if (!_options.Enabled)
            return RouteTarget.Primary;

        // App-name overrides
        if (appName != null && _alwaysPrimaryApps.Contains(appName))
            return RouteTarget.Primary;

        if (appName != null && _alwaysReadOnlyApps.Contains(appName))
        {
            _readOnlyConnectionUsed = true;
            return RouteTarget.ReadOnly;
        }

        // Active transaction — must go to primary
        if (_transactionTracker.InTransaction)
            return RouteTarget.Primary;

        // Only sp_executesql with a parseable read-only SQL payload can go to read-only
        if (string.Equals(procName, "sp_executesql", StringComparison.OrdinalIgnoreCase)
            && QueryClassifier.IsReadOnly(sqlText))
        {
            _readOnlyConnectionUsed = true;
            _logger.LogDebug("Routing sp_executesql to read-only replica");
            return RouteTarget.ReadOnly;
        }

        return RouteTarget.Primary;
    }
}

/// <summary>
/// Target connection for a query.
/// </summary>
public enum RouteTarget
{
    /// <summary>Route to the primary read-write connection.</summary>
    Primary,

    /// <summary>Route to the read-only replica connection.</summary>
    ReadOnly,
}
