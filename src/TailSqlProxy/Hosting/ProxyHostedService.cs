using Microsoft.Extensions.Hosting;
using TailSqlProxy.Proxy;

namespace TailSqlProxy.Hosting;

public class ProxyHostedService : BackgroundService
{
    private readonly TdsProxyServer _proxy;

    public ProxyHostedService(TdsProxyServer proxy)
    {
        _proxy = proxy;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        return _proxy.StartAsync(stoppingToken);
    }
}
