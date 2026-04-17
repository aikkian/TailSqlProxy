using System.Net.Sockets;

namespace TailSqlProxy.Proxy;

internal static class SocketKeepAlive
{
    // Azure Load Balancer drops idle TCP connections after 4 min (max 30 min).
    // Probe after 60s idle, every 30s, so hour-long queries survive the LB timer.
    public static void Enable(Socket socket)
    {
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 60);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 30);
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 5);
        }
        catch (SocketException) { /* retry-count not supported on macOS dev boxes */ }
    }
}
