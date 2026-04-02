using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using TailSqlProxy.Configuration;
using TailSqlProxy.Hosting;
using TailSqlProxy.Logging;
using TailSqlProxy.Proxy;
using TailSqlProxy.Rules;

var builder = Host.CreateApplicationBuilder(args);

// Serilog for application logging
builder.Services.AddSerilog(config => config
    .ReadFrom.Configuration(builder.Configuration)
    .WriteTo.Console(outputTemplate: "{Timestamp:HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}"));

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
