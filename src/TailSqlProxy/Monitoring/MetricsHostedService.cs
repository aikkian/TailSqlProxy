using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Prometheus;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Monitoring;

/// <summary>
/// Hosts a lightweight HTTP server that exposes Prometheus metrics at /metrics.
/// Only starts when Metrics.Enabled is true.
/// </summary>
public sealed class MetricsHostedService : BackgroundService
{
    private readonly int _port;
    private readonly ILogger<MetricsHostedService> _logger;
    private HttpListener? _httpListener;

    public MetricsHostedService(
        IOptions<MetricsOptions> options,
        ILogger<MetricsHostedService> logger)
    {
        _port = options.Value.Port;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _httpListener = new HttpListener();
        _httpListener.Prefixes.Add($"http://+:{_port}/metrics/");

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

        _logger.LogInformation("Prometheus metrics endpoint listening on http://0.0.0.0:{Port}/metrics/", _port);

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
            using var ms = new MemoryStream();
            await Metrics.DefaultRegistry.CollectAndExportAsTextAsync(ms);

            context.Response.ContentType = "text/plain; version=0.0.4; charset=utf-8";
            context.Response.StatusCode = 200;

            ms.Position = 0;
            await ms.CopyToAsync(context.Response.OutputStream);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error serializing metrics");
            context.Response.StatusCode = 500;
        }
        finally
        {
            context.Response.Close();
        }
    }

    public override void Dispose()
    {
        _httpListener?.Close();
        base.Dispose();
    }
}
