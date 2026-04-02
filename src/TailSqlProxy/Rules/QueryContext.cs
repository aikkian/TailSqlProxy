namespace TailSqlProxy.Rules;

public sealed class QueryContext
{
    public required string SqlText { get; init; }
    public string? ProcedureName { get; init; }
    public bool IsRpc { get; init; }
    public string? ClientIp { get; init; }
    public string? Username { get; init; }
    public string? Database { get; init; }
    public string? AppName { get; init; }
}
