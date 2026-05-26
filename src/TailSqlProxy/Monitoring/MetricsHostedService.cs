using System.Net;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Prometheus;
using TailSqlProxy.Configuration;
using TailSqlProxy.Proxy;

namespace TailSqlProxy.Monitoring;

/// <summary>
/// Hosts a lightweight HTTP server that exposes Prometheus metrics at /metrics
/// and a load-balancer health probe at /healthz.
/// Only starts when Metrics.Enabled is true.
/// </summary>
public sealed class MetricsHostedService : BackgroundService
{
    private readonly int _port;
    private readonly TdsProxyServer _proxyServer;
    private readonly ILogger<MetricsHostedService> _logger;
    private HttpListener? _httpListener;

    // Trip the health probe to 503 once we're within this fraction of the connection cap,
    // so a load balancer can route around an instance before it actually starts rejecting.
    private const double UnhealthyFraction = 0.9;

    public MetricsHostedService(
        IOptions<MetricsOptions> options,
        TdsProxyServer proxyServer,
        ILogger<MetricsHostedService> logger)
    {
        _port = options.Value.Port;
        _proxyServer = proxyServer;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _httpListener = new HttpListener();
        _httpListener.Prefixes.Add($"http://+:{_port}/");

        try
        {
            _httpListener.Start();
        }
        catch (HttpListenerException ex)
        {
            _logger.LogError(ex,
                "Failed to start metrics HTTP listener on port {Port}. " +
                "On Linux, try: setcap cap_net_bind_service=+ep or use a port > 1024",
                _port);
            return;
        }

        _logger.LogInformation(
            "Metrics+health endpoint listening on http://0.0.0.0:{Port}/ (/metrics, /healthz)",
            _port);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var context = await _httpListener.GetContextAsync().WaitAsync(stoppingToken);
                _ = HandleRequestAsync(context);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (HttpListenerException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error handling metrics request");
            }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        try
        {
            var path = context.Request.Url?.AbsolutePath ?? "/";

            if (path.StartsWith("/metrics", StringComparison.Ordinal))
            {
                await ServeMetricsAsync(context);
            }
            else if (path.StartsWith("/healthz", StringComparison.Ordinal))
            {
                await ServeHealthAsync(context);
            }
            else
            {
                context.Response.StatusCode = 404;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error serving request {Path}",
                context.Request.Url?.AbsolutePath);
            context.Response.StatusCode = 500;
        }
        finally
        {
            context.Response.Close();
        }
    }

    private static async Task ServeMetricsAsync(HttpListenerContext context)
    {
        using var ms = new MemoryStream();
        await Metrics.DefaultRegistry.CollectAndExportAsTextAsync(ms);

        context.Response.ContentType = "text/plain; version=0.0.4; charset=utf-8";
        context.Response.StatusCode = 200;

        ms.Position = 0;
        await ms.CopyToAsync(context.Response.OutputStream);
    }

    private async Task ServeHealthAsync(HttpListenerContext context)
    {
        var active = _proxyServer.ActiveConnections;
        var max = _proxyServer.MaxConcurrentConnections;
        var threshold = (int)(max * UnhealthyFraction);
        var healthy = active < threshold;

        var body = $"{{\"status\":\"{(healthy ? "ok" : "overloaded")}\"," +
                   $"\"active\":{active},\"max\":{max},\"threshold\":{threshold}}}";
        var bytes = Encoding.UTF8.GetBytes(body);

        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.StatusCode = healthy ? 200 : 503;
        context.Response.ContentLength64 = bytes.Length;
        await context.Response.OutputStream.WriteAsync(bytes);
    }

    public override void Dispose()
    {
        _httpListener?.Close();
        base.Dispose();
    }
}
