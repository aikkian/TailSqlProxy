using TailSqlProxy.Rules;

namespace TailSqlProxy.Logging;

public interface IAuditLogger
{
    void LogQuery(QueryContext context);
    void LogBlocked(QueryContext context, string reason);
    void LogConnection(string clientIp, string? username, string? database, string? appName);
    void LogDisconnection(string clientIp, string? username);
}
