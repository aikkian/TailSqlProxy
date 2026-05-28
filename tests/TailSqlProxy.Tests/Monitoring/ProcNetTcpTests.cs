using System.Net;
using FluentAssertions;
using TailSqlProxy.Monitoring;
using Xunit;

namespace TailSqlProxy.Tests.Monitoring;

public class ProcNetTcpTests
{
    // Real captures from /proc/net/tcp on the production host. The full file has a
    // header line + many rows; we test the parser against representative samples.
    private const string ListenLineVenus =
        "   2: 3600000A:0599 00000000:0000 0A 00000000:00000000 00:00000000 00000000   978        0 16022 1 0000000000000000 100 0 0 10 0";

    private const string EstablishedLine =
        "   5: 3600000A:0599 6B380C3C:E2A4 01 00000000:00000000 02:0009AB29 00000000   978        0 17684 4 0000000000000000 25 4 30 10 -1";

    [Theory]
    [InlineData("10.0.0.54", 1433, "3600000A:0599")]
    [InlineData("10.0.0.45", 1433, "2D00000A:0599")]
    [InlineData("0.0.0.0", 1433, "00000000:0599")]
    [InlineData("127.0.0.1", 80, "0100007F:0050")]
    [InlineData("192.168.1.1", 9090, "0101A8C0:2382")]
    public void FormatLocalAddress_matches_proc_net_tcp_encoding(string ip, int port, string expected)
    {
        ProcNetTcp.FormatLocalAddress(IPAddress.Parse(ip), port).Should().Be(expected);
    }

    [Fact]
    public void FormatLocalAddress_returns_null_for_ipv6()
    {
        ProcNetTcp.FormatLocalAddress(IPAddress.IPv6Loopback, 1433).Should().BeNull();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(125)]
    [InlineData(4096)]
    public void TryParseRxQueue_parses_listen_row_with_various_queue_depths(int depth)
    {
        // Build a /proc/net/tcp listen row with the given rx_queue (hex-encoded).
        // tx_queue is the backlog (max), rx_queue is the current depth.
        var line = $"   2: 3600000A:0599 00000000:0000 0A 00000000:{depth:X8} 00:00000000 00000000   978        0 16022 1 0000000000000000 100 0 0 10 0";

        ProcNetTcp.TryParseRxQueue(line, "3600000A:0599", out int rx).Should().BeTrue();
        rx.Should().Be(depth);
    }

    [Fact]
    public void TryParseRxQueue_returns_false_for_wrong_local_address()
    {
        ProcNetTcp.TryParseRxQueue(ListenLineVenus, "2D00000A:0599", out _).Should().BeFalse();
    }

    [Fact]
    public void TryParseRxQueue_returns_false_for_non_listen_state()
    {
        // EstablishedLine has state=01 (ESTABLISHED), not 0A (LISTEN). We must skip
        // it even when the local address matches — its tx/rx queue semantics differ.
        ProcNetTcp.TryParseRxQueue(EstablishedLine, "3600000A:0599", out _).Should().BeFalse();
    }

    [Fact]
    public void TryParseRxQueue_returns_false_for_malformed_line()
    {
        ProcNetTcp.TryParseRxQueue("garbage", "3600000A:0599", out _).Should().BeFalse();
        ProcNetTcp.TryParseRxQueue("", "3600000A:0599", out _).Should().BeFalse();
    }

    [Fact]
    public void TryParseRxQueue_is_case_insensitive_on_address_match()
    {
        ProcNetTcp.TryParseRxQueue(ListenLineVenus, "3600000a:0599", out int rx).Should().BeTrue();
        rx.Should().Be(0);
    }

    [Fact]
    public void GetAcceptQueueDepth_returns_minus_one_when_proc_missing()
    {
        // On macOS / Windows dev boxes /proc/net/tcp doesn't exist; we must not throw.
        if (File.Exists("/proc/net/tcp"))
        {
            // On Linux, querying for an address we definitely don't listen on returns -1.
            var depth = ProcNetTcp.GetAcceptQueueDepth(IPAddress.Parse("203.0.113.99"), 65535);
            depth.Should().Be(-1);
        }
        else
        {
            var depth = ProcNetTcp.GetAcceptQueueDepth(IPAddress.Loopback, 1433);
            depth.Should().Be(-1);
        }
    }
}
