using System.Globalization;
using System.Net;

namespace TailSqlProxy.Monitoring;

/// <summary>
/// Reads the current TCP accept queue depth for a LISTEN socket from /proc/net/tcp.
/// Linux-only. Returns -1 when the listener can't be found or /proc isn't available.
/// </summary>
internal static class ProcNetTcp
{
    private const string ProcPath = "/proc/net/tcp";

    /// <summary>
    /// Returns the current accept queue depth (rx_queue) for the listener bound to
    /// <paramref name="address"/>:<paramref name="port"/>, or -1 if not found.
    /// </summary>
    public static int GetAcceptQueueDepth(IPAddress address, int port)
    {
        if (!File.Exists(ProcPath)) return -1;

        var needle = FormatLocalAddress(address, port);
        if (needle is null) return -1;

        using var reader = new StreamReader(ProcPath);
        string? line;
        bool firstLine = true;
        while ((line = reader.ReadLine()) is not null)
        {
            if (firstLine) { firstLine = false; continue; } // header
            if (TryParseRxQueue(line, needle, out int depth))
                return depth;
        }
        return -1;
    }

    internal static bool TryParseRxQueue(string line, string expectedLocalAddr, out int rxQueue)
    {
        rxQueue = -1;
        // /proc/net/tcp columns (space-separated, with leading "sl:" index):
        //   sl  local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode
        // Skip the leading "  0:" index token, then expect local_address at index 1, state at 3, queue at 4.
        var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 5) return false;

        if (!fields[1].Equals(expectedLocalAddr, StringComparison.OrdinalIgnoreCase)) return false;
        if (fields[3] != "0A") return false; // not LISTEN

        var colon = fields[4].IndexOf(':');
        if (colon < 0) return false;
        var rxHex = fields[4].AsSpan(colon + 1);
        return int.TryParse(rxHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out rxQueue);
    }

    /// <summary>
    /// Encodes an IPv4 address + port in the format /proc/net/tcp uses:
    /// LE byte order for the address, BE for the port, both uppercase hex.
    /// Example: 10.0.0.54:1433 → "3600000A:0599".
    /// </summary>
    internal static string? FormatLocalAddress(IPAddress address, int port)
    {
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out int written) || written != 4) return null;
        // /proc/net/tcp writes the 32-bit address in host byte order on a little-endian box,
        // which prints as the bytes reversed compared to dotted-quad reading order.
        return $"{bytes[3]:X2}{bytes[2]:X2}{bytes[1]:X2}{bytes[0]:X2}:{port:X4}";
    }
}
