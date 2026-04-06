using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;
using Serilog.Sinks.Datadog.Logs;
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
        var proxyOptions = options.Value;
        var logPath = proxyOptions.AuditLogPath ?? "logs/audit-.log";
        var jsonLogPath = proxyOptions.AuditJsonLogPath;

        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                path: logPath,
                rollingInterval: RollingInterval.Day,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fffZ} [{Level:u3}] {Message:lj}{NewLine}");

        // JSON structured log (for SIEM ingestion)
        if (!string.IsNullOrWhiteSpace(jsonLogPath))
        {
            loggerConfig = loggerConfig.WriteTo.File(
                formatter: new CompactJsonFormatter(),
                path: jsonLogPath,
                rollingInterval: RollingInterval.Day);
        }

        var dd = proxyOptions.Datadog;
        if (dd.Enabled && !string.IsNullOrWhiteSpace(dd.ApiKey))
        {
            var ddConfig = new DatadogConfiguration();
            loggerConfig = loggerConfig
                .WriteTo.DatadogLogs(
                    apiKey: dd.ApiKey,
                    source: dd.Source,
                    service: dd.Service,
                    host: dd.Host ?? Environment.MachineName,
                    tags: dd.Tags ?? [],
                    configuration: ddConfig)
                .Enrich.WithProperty("dd.service", dd.Service)
                .Enrich.WithProperty("dd.source", dd.Source);
        }

        _auditLog = loggerConfig
            .CreateLogger()
            .ForContext(Serilog.Core.Constants.SourceContextPropertyName, "Audit");
    }

    public void LogQuery(QueryContext context)
    {
        _auditLog.Information(
            "QUERY | Time={UtcDateTime} | Session={SessionId} | IP={ClientIp} | Host={HostName} | " +
            "User={Username} | DB={Database} | App={AppName} | Duration={DurationMs}ms | " +
            "Rows={RowCount} | SQL={SqlText}",
            DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            context.SessionId,
            context.ClientIp, context.HostName, context.Username, context.Database, context.AppName,
            context.DurationMs?.ToString("F1") ?? "-",
            context.RowCount?.ToString() ?? "-",
            Truncate(context.SqlText));
    }

    public void LogBlocked(QueryContext context, string reason)
    {
        _auditLog.Warning(
            "BLOCKED | Time={UtcDateTime} | Session={SessionId} | IP={ClientIp} | Host={HostName} | " +
            "User={Username} | DB={Database} | App={AppName} | Reason={Reason} | SQL={SqlText}",
            DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            context.SessionId,
            context.ClientIp, context.HostName, context.Username, context.Database, context.AppName,
            reason, Truncate(context.SqlText));
    }

    public void LogConnection(string clientIp, string? username, string? database, string? appName)
    {
        LogConnection(clientIp, username, database, appName, null);
    }

    public void LogConnection(string clientIp, string? username, string? database, string? appName, string? sessionId)
    {
        _auditLog.Information(
            "CONNECT | Session={SessionId} | IP={ClientIp} | User={Username} | DB={Database} | App={AppName}",
            sessionId, clientIp, username, database, appName);
    }

    public void LogDisconnection(string clientIp, string? username)
    {
        LogDisconnection(clientIp, username, null);
    }

    public void LogDisconnection(string clientIp, string? username, string? sessionId)
    {
        _auditLog.Information(
            "DISCONNECT | Session={SessionId} | IP={ClientIp} | User={Username}",
            sessionId, clientIp, username);
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
