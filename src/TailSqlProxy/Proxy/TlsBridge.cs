using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace TailSqlProxy.Proxy;

public class TlsBridge
{
    private readonly CertificateProvider _certificateProvider;
    private readonly ILogger<TlsBridge> _logger;

    public TlsBridge(CertificateProvider certificateProvider, ILogger<TlsBridge> logger)
    {
        _certificateProvider = certificateProvider;
        _logger = logger;
    }

    /// <summary>
    /// Establishes TLS on both sides for TDS 8.0 (Azure SQL default).
    /// In TDS 8.0, the entire connection is wrapped in TLS from the first byte.
    /// </summary>
    public async Task<(SslStream ClientSsl, SslStream ServerSsl)> EstablishTds8TlsAsync(
        Stream clientRawStream,
        Stream serverRawStream,
        string targetServerHostname,
        CancellationToken ct)
    {
        var proxyCert = _certificateProvider.GetCertificate();

        // Step 1: Connect to Azure SQL with TLS (proxy acts as TLS client)
        _logger.LogDebug("Initiating TLS handshake with target server: {Host}", targetServerHostname);
        var serverSsl = new SslStream(serverRawStream, leaveInnerStreamOpen: false, ValidateServerCertificate);

        await serverSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = targetServerHostname,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = ValidateServerCertificate,
        }, ct);
        _logger.LogDebug("TLS established with target server (Protocol: {Protocol})", serverSsl.SslProtocol);

        // Step 2: Accept TLS from client (proxy acts as TLS server with self-signed cert)
        _logger.LogDebug("Accepting TLS handshake from client");
        var clientSsl = new SslStream(clientRawStream, leaveInnerStreamOpen: false);

        await clientSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = proxyCert,
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, ct);
        _logger.LogDebug("TLS established with client (Protocol: {Protocol})", clientSsl.SslProtocol);

        return (clientSsl, serverSsl);
    }

    /// <summary>
    /// Establishes TLS with a TDS 7.x server.
    /// TLS handshake bytes are wrapped inside TDS PreLogin packets.
    /// After handshake, switches to passthrough for direct TLS record flow.
    /// Must be called AFTER the PreLogin exchange has completed on the raw stream.
    /// </summary>
    public async Task<SslStream> EstablishServerTds7TlsAsync(
        Stream serverRawStream,
        string targetServerHostname,
        CancellationToken ct)
    {
        _logger.LogDebug("Initiating TDS 7.x TLS handshake with server: {Host}", targetServerHostname);
        var serverWrapper = new TdsPreLoginWrapperStream(serverRawStream);
        var serverSsl = new SslStream(serverWrapper, leaveInnerStreamOpen: true, ValidateServerCertificate);

        await serverSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = targetServerHostname,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = ValidateServerCertificate,
        }, ct);

        serverWrapper.EnablePassthrough();
        _logger.LogDebug("TLS established with TDS 7.x server (Protocol: {Protocol})", serverSsl.SslProtocol);

        return serverSsl;
    }

    /// <summary>
    /// Accepts raw TLS from a TDS 8.0 client (no TDS wrapping — pure TLS from first byte).
    /// </summary>
    public async Task<SslStream> AcceptClientTlsAsync(
        Stream clientRawStream,
        CancellationToken ct)
    {
        var proxyCert = _certificateProvider.GetCertificate();

        _logger.LogDebug("Accepting raw TLS from TDS 8.0 client");
        var clientSsl = new SslStream(clientRawStream, leaveInnerStreamOpen: false);

        await clientSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = proxyCert,
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, ct);
        _logger.LogDebug("TLS established with TDS 8.0 client (Protocol: {Protocol})", clientSsl.SslProtocol);

        return clientSsl;
    }

    /// <summary>
    /// Establishes TLS with a TDS 7.x client.
    /// TLS handshake bytes are wrapped inside TDS PreLogin packets (type 0x12).
    /// After the handshake completes, the wrapper switches to passthrough mode
    /// so subsequent TLS records flow directly over the raw stream.
    /// </summary>
    public async Task<SslStream> EstablishClientTds7TlsAsync(
        Stream clientRawStream,
        CancellationToken ct)
    {
        var proxyCert = _certificateProvider.GetCertificate();

        _logger.LogDebug("Accepting TDS 7.x TLS handshake from client (wrapped in PreLogin packets)");
        var clientWrapper = new TdsPreLoginWrapperStream(clientRawStream);
        var clientSsl = new SslStream(clientWrapper, leaveInnerStreamOpen: true);

        await clientSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = proxyCert,
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        }, ct);

        // Switch wrapper to passthrough — after TLS handshake, TLS records
        // flow directly on the wire without TDS PreLogin wrapping
        clientWrapper.EnablePassthrough();
        _logger.LogDebug("TLS established with TDS 7.x client (Protocol: {Protocol})", clientSsl.SslProtocol);

        return clientSsl;
    }

    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // Trust the Azure SQL server certificate
        return true;
    }
}

/// <summary>
/// Custom stream adapter for TDS 7.x TLS handshake.
/// Wraps TLS handshake bytes in TDS PreLogin packets (type 0x12) for writing,
/// and strips TDS headers when reading.
/// </summary>
internal class TdsPreLoginWrapperStream : Stream
{
    private readonly Stream _inner;
    private readonly MemoryStream _readBuffer = new();
    private bool _readBufferConsumed = true;
    private volatile bool _passthrough;

    public TdsPreLoginWrapperStream(Stream inner)
    {
        _inner = inner;
    }

    /// <summary>
    /// Switches to passthrough mode — after the TLS handshake completes,
    /// TLS records flow directly without TDS PreLogin wrapping.
    /// </summary>
    public void EnablePassthrough() => _passthrough = true;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_passthrough)
            return _inner.Read(buffer, offset, count);

        if (_readBufferConsumed || _readBuffer.Position >= _readBuffer.Length)
        {
            // Read next TDS packet from inner stream
            var header = new byte[8];
            int headerRead = ReadExact(_inner, header, 0, 8);
            if (headerRead < 8)
                return 0;

            int length = (header[2] << 8) | header[3];
            int payloadLen = length - 8;

            if (payloadLen <= 0)
                return 0;

            var payload = new byte[payloadLen];
            int payloadRead = ReadExact(_inner, payload, 0, payloadLen);
            if (payloadRead < payloadLen)
                return 0;

            _readBuffer.SetLength(0);
            _readBuffer.Write(payload, 0, payloadLen);
            _readBuffer.Position = 0;
            _readBufferConsumed = false;
        }

        int result = _readBuffer.Read(buffer, offset, count);
        if (_readBuffer.Position >= _readBuffer.Length)
            _readBufferConsumed = true;
        return result;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_passthrough)
        {
            _inner.Write(buffer, offset, count);
            _inner.Flush();
            return;
        }

        // Wrap in TDS PreLogin packet
        int packetLen = count + 8;
        var packet = new byte[packetLen];
        packet[0] = 0x12; // PreLogin
        packet[1] = 0x01; // EOM
        packet[2] = (byte)(packetLen >> 8);
        packet[3] = (byte)(packetLen & 0xFF);
        // SPID, PacketID, Window = 0
        Array.Copy(buffer, offset, packet, 8, count);
        _inner.Write(packet, 0, packetLen);
        _inner.Flush();
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        if (_passthrough)
            return _inner.ReadAsync(buffer, offset, count, ct);
        return base.ReadAsync(buffer, offset, count, ct);
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_passthrough)
            return _inner.ReadAsync(buffer, ct);
        return base.ReadAsync(buffer, ct);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        if (_passthrough)
            return _inner.WriteAsync(buffer, offset, count, ct);
        return base.WriteAsync(buffer, offset, count, ct);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_passthrough)
            return _inner.WriteAsync(buffer, ct);
        return base.WriteAsync(buffer, ct);
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    private static int ReadExact(Stream stream, byte[] buffer, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            int read = stream.Read(buffer, offset + total, count - total);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
