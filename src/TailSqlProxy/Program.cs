using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Sinks.Datadog.Logs;
using TailSqlProxy.Configuration;
using TailSqlProxy.Hosting;
using TailSqlProxy.Logging;
using TailSqlProxy.Proxy;
using TailSqlProxy.Rules;

var builder = Host.CreateApplicationBuilder(args);

// Serilog for application logging
builder.Services.AddSerilog(config =>
{
    config
        .ReadFrom.Configuration(builder.Configuration)
        .WriteTo.Console(outputTemplate: "{Timestamp:HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}");

    // Conditionally add Datadog sink for application-level logs
    var ddSection = builder.Configuration.GetSection("Proxy:Datadog");
    if (ddSection.GetValue<bool>("Enabled"))
    {
        var apiKey = ddSection.GetValue<string>("ApiKey") ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            var service = ddSection.GetValue<string>("Service") ?? "tailsqlproxy";
            var source = ddSection.GetValue<string>("Source") ?? "csharp";
            var host = ddSection.GetValue<string>("Host") ?? Environment.MachineName;
            var tags = ddSection.GetSection("Tags").Get<string[]>() ?? [];

            config.WriteTo.DatadogLogs(
                apiKey: apiKey,
                source: source,
                service: service,
                host: host,
                tags: tags,
                configuration: new DatadogConfiguration());
        }
    }
});

// Configuration
builder.Services.Configure<ProxyOptions>(builder.Configuration.GetSection("Proxy"));
builder.Services.Configure<TargetServerOptions>(builder.Configuration.GetSection("TargetServer"));
builder.Services.Configure<RuleOptions>(builder.Configuration.GetSection("Rules"));

// Proxy infrastructure
builder.Services.AddSingleton<CertificateProvider>();
builder.Services.AddSingleton<TlsBridge>();
builder.Services.AddSingleton<TdsProxyServer>();
builder.Services.AddScoped<ClientSession>();

// Rules
builder.Services.AddSingleton<IQueryRule, SqlInjectionRule>();
builder.Services.AddSingleton<IQueryRule, UnboundedSelectRule>();
builder.Services.AddSingleton<IQueryRule, UnboundedDeleteRule>();
builder.Services.AddSingleton<IQueryRule, SsmsMetadataRule>();
builder.Services.AddSingleton<IRuleEngine, RuleEngine>();

// Audit logging
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();

// Hosted service
builder.Services.AddHostedService<ProxyHostedService>();

var host = builder.Build();
await host.RunAsync();
