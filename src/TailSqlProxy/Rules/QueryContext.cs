namespace TailSqlProxy.Rules;

public sealed class QueryContext
{
    public required string SqlText { get; init; }
    public string? ProcedureName { get; init; }
    public bool IsRpc { get; init; }
    public string? ClientIp { get; init; }
    public string? HostName { get; init; }
    public string? Username { get; init; }
    public string? Database { get; init; }
    public string? AppName { get; init; }

    /// <summary>Unique session ID for correlating queries within a connection.</summary>
    public string? SessionId { get; init; }

    /// <summary>Query execution start time (UTC), set before forwarding to server.</summary>
    public DateTime? StartTimeUtc { get; set; }

    /// <summary>Query duration in milliseconds, set after server response completes.</summary>
    public double? DurationMs { get; set; }

    /// <summary>Row count from the DONE token, set after server response completes.</summary>
    public long? RowCount { get; set; }
}
