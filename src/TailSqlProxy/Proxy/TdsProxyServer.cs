using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Proxy;

public class TdsProxyServer
{
    private readonly ProxyOptions _options;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TdsProxyServer> _logger;
    private TcpListener? _listener;
    private int _activeConnections;

    public TdsProxyServer(
        IOptions<ProxyOptions> options,
        IServiceProvider serviceProvider,
        ILogger<TdsProxyServer> logger)
    {
        _options = options.Value;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        var address = IPAddress.Parse(_options.ListenAddress);
        _listener = new TcpListener(address, _options.ListenPort);
        _listener.Start();

        _logger.LogInformation("TailSqlProxy TDS proxy listening on {Address}:{Port}",
            _options.ListenAddress, _options.ListenPort);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(ct);
                var clientEndpoint = client.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogInformation("New connection from {ClientIp}", clientEndpoint?.Address);

                // Atomic increment-and-check: increment first, then rollback if over limit
                var count = Interlocked.Increment(ref _activeConnections);
                if (count > _options.MaxConcurrentConnections)
                {
                    Interlocked.Decrement(ref _activeConnections);
                    _logger.LogWarning("Max concurrent connections ({Max}) reached. Rejecting connection from {ClientIp}",
                        _options.MaxConcurrentConnections, clientEndpoint?.Address);
                    client.Close();
                    continue;
                }

                _ = HandleClientAsync(client, ct);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("TDS proxy shutting down");
        }
        finally
        {
            _listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        // Connection already counted via Interlocked.Increment in StartAsync
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var session = scope.ServiceProvider.GetRequiredService<ClientSession>();
            await session.RunAsync(client, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var clientEndpoint = client.Client.RemoteEndPoint as IPEndPoint;
            _logger.LogError(ex, "Error handling connection from {ClientIp}", clientEndpoint?.Address);
        }
        finally
        {
            Interlocked.Decrement(ref _activeConnections);
            try { client.Close(); } catch { /* ignore */ }
        }
    }
}
