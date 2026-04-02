using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;
using TailSqlProxy.Configuration;
using TailSqlProxy.Rules;
using ILogger = Serilog.ILogger;

namespace TailSqlProxy.Logging;

public class AuditLogger : IAuditLogger, IDisposable
{
    private readonly ILogger _auditLog;
    private const int MaxSqlLength = 4000;

    public AuditLogger(IOptions<ProxyOptions> options)
    {
        var logPath = options.Value.AuditLogPath ?? "logs/audit-.log";
        _auditLog = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                path: logPath,
                rollingInterval: RollingInterval.Day,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}")
            .CreateLogger();
    }

    public void LogQuery(QueryContext context)
    {
        _auditLog.Information(
            "QUERY | IP={ClientIp} | User={Username} | DB={Database} | App={AppName} | SQL={SqlText}",
            context.ClientIp, context.Username, context.Database, context.AppName,
            Truncate(context.SqlText));
    }

    public void LogBlocked(QueryContext context, string reason)
    {
        _auditLog.Warning(
            "BLOCKED | IP={ClientIp} | User={Username} | DB={Database} | App={AppName} | Reason={Reason} | SQL={SqlText}",
            context.ClientIp, context.Username, context.Database, context.AppName,
            reason, Truncate(context.SqlText));
    }

    public void LogConnection(string clientIp, string? username, string? database, string? appName)
    {
        _auditLog.Information(
            "CONNECT | IP={ClientIp} | User={Username} | DB={Database} | App={AppName}",
            clientIp, username, database, appName);
    }

    public void LogDisconnection(string clientIp, string? username)
    {
        _auditLog.Information(
            "DISCONNECT | IP={ClientIp} | User={Username}",
            clientIp, username);
    }

    private static string Truncate(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        return text.Length <= MaxSqlLength ? text : text[..MaxSqlLength] + "...";
    }

    public void Dispose()
    {
        (_auditLog as IDisposable)?.Dispose();
    }
}
