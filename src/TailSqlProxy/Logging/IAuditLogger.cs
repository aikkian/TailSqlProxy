using TailSqlProxy.Rules;

namespace TailSqlProxy.Logging;

public interface IAuditLogger
{
    void LogQuery(QueryContext context);
    void LogBlocked(QueryContext context, string reason);
    void LogSlowQuery(QueryContext context);
    void LogTimeoutKilled(QueryContext context, double timeoutMs);
    void LogConnection(string clientIp, string? username, string? database, string? appName);
    void LogConnection(string clientIp, string? username, string? database, string? appName, string? sessionId);
    void LogDisconnection(string clientIp, string? username);
    void LogDisconnection(string clientIp, string? username, string? sessionId);
}
