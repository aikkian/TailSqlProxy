using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;

namespace TailSqlProxy.Monitoring;

/// <summary>
/// Watchdog that detects when the proxy's accept loop has wedged.
///
/// Symptom we're guarding against (observed in production 2026-05-28): a Serilog/
/// journald interaction wedged a worker thread inside a synchronous Console sink
/// write. The ThreadPool then starved, the accept loop's async continuation never
/// ran, and the kernel-side accept queue (rx_queue) grew unbounded while the
/// userspace process kept appearing "healthy" by every other measure.
///
/// We read the LISTEN socket's rx_queue directly from /proc/net/tcp and exit the
/// process if it stays above a threshold for several consecutive checks. systemd's
/// Restart=on-failure brings us back with a clean state.
///
/// Linux-only. No-op when /proc/net/tcp isn't readable.
/// </summary>
public sealed class AcceptQueueWatchdog : BackgroundService
{
    private readonly ProxyOptions _options;
    private readonly ILogger<AcceptQueueWatchdog> _logger;

    // Tunables — conservative defaults so we don't false-positive on bursty traffic.
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);
    private const int StuckThreshold = 50;
    private const int ConsecutiveStuckChecks = 4; // 4 × 30s = 2 minutes
    private const int ExitCode = 75; // sysexits.h EX_TEMPFAIL — systemd treats as failure

    public AcceptQueueWatchdog(
        IOptions<ProxyOptions> options,
        ILogger<AcceptQueueWatchdog> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!IPAddress.TryParse(_options.ListenAddress, out var listenAddr))
        {
            _logger.LogWarning(
                "Watchdog disabled: ListenAddress {Address} is not a valid IP",
                _options.ListenAddress);
            return;
        }

        int consecutiveStuck = 0;
        bool everSawValidData = false;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }

            int depth;
            try
            {
                depth = ProcNetTcp.GetAcceptQueueDepth(listenAddr, _options.ListenPort);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Watchdog: failed to read /proc/net/tcp");
                continue;
            }

            if (depth < 0)
            {
                if (!everSawValidData)
                {
                    _logger.LogDebug(
                        "Watchdog: listener not yet found in /proc/net/tcp (depth={Depth})",
                        depth);
                }
                continue;
            }
            everSawValidData = true;

            if (depth >= StuckThreshold)
            {
                consecutiveStuck++;
                _logger.LogWarning(
                    "Watchdog: accept queue depth {Depth} ≥ {Threshold} on {Address}:{Port} ({Count}/{Max} consecutive)",
                    depth, StuckThreshold, _options.ListenAddress, _options.ListenPort,
                    consecutiveStuck, ConsecutiveStuckChecks);

                if (consecutiveStuck >= ConsecutiveStuckChecks)
                {
                    _logger.LogCritical(
                        "Watchdog: accept loop appears wedged (rx_queue={Depth} for ~{Duration}). " +
                        "Exiting with code {ExitCode} so systemd can restart us.",
                        depth, CheckInterval * ConsecutiveStuckChecks, ExitCode);

                    // Give the async logger a moment to flush before we hard-exit.
                    await Task.Delay(TimeSpan.FromMilliseconds(500), CancellationToken.None);
                    Environment.Exit(ExitCode);
                }
            }
            else
            {
                if (consecutiveStuck > 0)
                {
                    _logger.LogInformation(
                        "Watchdog: accept queue recovered to {Depth}, resetting stuck counter",
                        depth);
                }
                consecutiveStuck = 0;
            }
        }
    }
}
