using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TailSqlProxy.Configuration;
using TailSqlProxy.Logging;
using TailSqlProxy.Protocol;
using TailSqlProxy.Protocol.Messages;
using TailSqlProxy.Rules;

namespace TailSqlProxy.Proxy;

public class ClientSession : IDisposable
{
    private readonly TargetServerOptions _targetOptions;
    private readonly ProxyOptions _proxyOptions;
    private readonly TlsBridge _tlsBridge;
    private readonly IRuleEngine _ruleEngine;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<ClientSession> _logger;

    private TcpClient? _serverConnection;
    private Stream? _clientStream;
    private Stream? _serverStream;
    private TdsMessageReader? _clientReader;
    private TdsMessageWriter? _clientWriter;
    private TdsMessageReader? _serverReader;
    private TdsMessageWriter? _serverWriter;

    // Write locks to prevent interleaved packet writes from concurrent tasks
    private readonly SemaphoreSlim _clientWriteLock = new(1, 1);
    private readonly SemaphoreSlim _serverWriteLock = new(1, 1);

    // Session state
    private readonly string _sessionId = Guid.NewGuid().ToString("N")[..12];
    private string? _clientIp;
    private string? _hostName;
    private string? _username;
    private string? _database;
    private string? _appName;

    // Timeout for response forwarding (prevents hung connections)
    private static readonly TimeSpan ResponseTimeout = TimeSpan.FromMinutes(5);

    public ClientSession(
        IOptions<TargetServerOptions> targetOptions,
        IOptions<ProxyOptions> proxyOptions,
        TlsBridge tlsBridge,
        IRuleEngine ruleEngine,
        IAuditLogger auditLogger,
        ILogger<ClientSession> logger)
    {
        _targetOptions = targetOptions.Value;
        _proxyOptions = proxyOptions.Value;
        _tlsBridge = tlsBridge;
        _ruleEngine = ruleEngine;
        _auditLogger = auditLogger;
        _logger = logger;
    }

    public async Task RunAsync(TcpClient client, CancellationToken ct)
    {
        _clientIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "unknown";

        try
        {
            // Peek at first byte to detect TDS version without consuming it
            var peekBuf = new byte[1];
            int peekRead = client.Client.Receive(peekBuf, 0, 1, System.Net.Sockets.SocketFlags.Peek);
            if (peekRead == 0) return;

            bool isTds8 = peekBuf[0] == 0x16; // TLS ClientHello

            // 1. Connect to target server
            _serverConnection = new TcpClient();
            _serverConnection.NoDelay = true;
            await _serverConnection.ConnectAsync(_targetOptions.Host, _targetOptions.Port, ct);
            _logger.LogDebug("Connected to target server {Host}:{Port}", _targetOptions.Host, _targetOptions.Port);

            var clientNetStream = client.GetStream();
            var serverNetStream = _serverConnection.GetStream();

            if (isTds8)
            {
                // TDS 8.0 client + TDS 7.x server bridging
                _logger.LogDebug("Detected TDS 8.0 client (TLS from first byte)");

                // Generate a PreLogin for the server (TDS 7.x requires PreLogin before TLS)
                var proxyPreLogin = BuildPreLoginPacket();
                await serverNetStream.WriteAsync(proxyPreLogin, ct);
                await serverNetStream.FlushAsync(ct);

                // Read server's PreLogin response (raw TCP)
                var rawServerReader = new TdsMessageReader(serverNetStream);
                var serverPreLoginMsg = await rawServerReader.ReadMessageAsync(ct);
                if (serverPreLoginMsg == null)
                    throw new InvalidOperationException("Server disconnected during PreLogin.");
                _logger.LogDebug("Server PreLogin response received");

                // TLS with server (TDS 7.x — wrapped in PreLogin packets)
                var serverSsl = await _tlsBridge.EstablishServerTds7TlsAsync(
                    serverNetStream, _targetOptions.Host, ct);
                _serverStream = serverSsl;

                // TLS with client (TDS 8.0 — raw TLS)
                var clientSsl = await _tlsBridge.AcceptClientTlsAsync(clientNetStream, ct);
                _clientStream = clientSsl;

                _clientReader = new TdsMessageReader(_clientStream);
                _clientWriter = new TdsMessageWriter(_clientStream);
                _serverReader = new TdsMessageReader(_serverStream);
                _serverWriter = new TdsMessageWriter(_serverStream);

                // Forward PreLogin exchange over TLS (client expects PreLogin over TLS in TDS 8.0)
                await ForwardPreLoginAsync(ct);
            }
            else
            {
                // TDS 7.x client + TDS 7.x server (JDBC, DataGrip)
                _logger.LogDebug("Detected TDS 7.x client (PreLogin first)");

                // Read client's PreLogin (raw TCP)
                var rawClientReader = new TdsMessageReader(clientNetStream);
                var clientPreLogin = await rawClientReader.ReadMessageAsync(ct);
                if (clientPreLogin == null)
                    throw new InvalidOperationException("Client disconnected during PreLogin.");
                _logger.LogDebug("Received TDS 7.x PreLogin from client ({Len} bytes)", clientPreLogin.Payload.Length);

                // Forward PreLogin to server (raw TCP)
                foreach (var pkt in clientPreLogin.Packets)
                    await serverNetStream.WriteAsync(pkt.RawBytes, ct);
                await serverNetStream.FlushAsync(ct);

                // Read server's PreLogin response (raw TCP)
                var rawServerReader = new TdsMessageReader(serverNetStream);
                var serverPreLogin = await rawServerReader.ReadMessageAsync(ct);
                if (serverPreLogin == null)
                    throw new InvalidOperationException("Server disconnected during PreLogin.");

                // Forward PreLogin response to client (raw TCP)
                foreach (var pkt in serverPreLogin.Packets)
                    await clientNetStream.WriteAsync(pkt.RawBytes, ct);
                await clientNetStream.FlushAsync(ct);
                _logger.LogDebug("PreLogin exchange complete");

                // TLS with server (TDS 7.x — wrapped in PreLogin packets)
                var serverSsl = await _tlsBridge.EstablishServerTds7TlsAsync(
                    serverNetStream, _targetOptions.Host, ct);
                _serverStream = serverSsl;

                // TLS with client (TDS 7.x — wrapped in PreLogin packets)
                var clientSsl = await _tlsBridge.EstablishClientTds7TlsAsync(clientNetStream, ct);
                _clientStream = clientSsl;

                _clientReader = new TdsMessageReader(_clientStream);
                _clientWriter = new TdsMessageWriter(_clientStream);
                _serverReader = new TdsMessageReader(_serverStream);
                _serverWriter = new TdsMessageWriter(_serverStream);
            }

            // Handle Login7 (extract user/db info, then forward)
            await HandleLogin7Async(ct);

            _auditLogger.LogConnection(_clientIp, _username, _database, _appName, _sessionId);

            // Bidirectional relay — two concurrent tasks for MARS support
            await RunBidirectionalRelayAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Session error for client {ClientIp}", _clientIp);
        }
        finally
        {
            _auditLogger.LogDisconnection(_clientIp, _username, _sessionId);
            _logger.LogInformation("Client {ClientIp} disconnected (User={Username})", _clientIp, _username);
        }
    }

    /// <summary>
    /// Builds a minimal TDS PreLogin packet for the proxy to send to TDS 7.x servers.
    /// Requests ENCRYPT_ON so the server agrees to TLS after PreLogin.
    /// </summary>
    private static byte[] BuildPreLoginPacket()
    {
        // PreLogin option tokens
        // VERSION: offset 0x15, length 6
        // ENCRYPTION: offset 0x1B, length 1
        // TERMINATOR: 0xFF
        var options = new byte[]
        {
            0x00, 0x00, 0x15, 0x00, 0x06, // VERSION token
            0x01, 0x00, 0x1B, 0x00, 0x01, // ENCRYPTION token
            0xFF,                           // TERMINATOR
        };

        var optionData = new byte[]
        {
            // Version: 16.0.0.0 (TDS 7.4)
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Encryption: ENCRYPT_ON (0x01)
            0x01,
        };

        int payloadLen = options.Length + optionData.Length;
        int packetLen = 8 + payloadLen;
        var packet = new byte[packetLen];

        // TDS header
        packet[0] = 0x12; // PreLogin
        packet[1] = 0x01; // EOM
        packet[2] = (byte)(packetLen >> 8);
        packet[3] = (byte)(packetLen & 0xFF);
        // SPID=0, PacketID=1, Window=0
        packet[6] = 0x01;

        Array.Copy(options, 0, packet, 8, options.Length);
        Array.Copy(optionData, 0, packet, 8 + options.Length, optionData.Length);

        return packet;
    }

    /// <summary>
    /// Runs two concurrent tasks:
    ///   1. Client→Server: reads client messages, inspects/blocks, forwards allowed ones to server
    ///   2. Server→Client: reads server packets and forwards them to client transparently
    /// When either side disconnects or errors, both tasks are cancelled.
    /// This supports MARS (Multiple Active Result Sets) where the client can send
    /// new queries while previous responses are still streaming back.
    /// </summary>
    private async Task RunBidirectionalRelayAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var clientToServerTask = RelayClientToServerAsync(cts.Token);
        var serverToClientTask = RelayServerToClientAsync(cts.Token);

        // Wait for either task to complete (disconnect or error)
        var completedTask = await Task.WhenAny(clientToServerTask, serverToClientTask);

        // Cancel the other direction
        await cts.CancelAsync();

        // Await both to observe exceptions
        try { await clientToServerTask; } catch (OperationCanceledException) { }
        try { await serverToClientTask; } catch (OperationCanceledException) { }

        // Propagate any non-cancellation exception from the first completed task
        if (completedTask.IsFaulted)
            await completedTask; // rethrows
    }

    /// <summary>
    /// Client→Server relay: reads TDS messages from client, inspects SQL Batch and RPC
    /// messages through the rule engine, blocks or forwards to server.
    /// </summary>
    private async Task RelayClientToServerAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var message = await _clientReader!.ReadMessageAsync(ct);
            if (message == null)
            {
                _logger.LogDebug("Client disconnected");
                break;
            }

            switch (message.Type)
            {
                case TdsPacketType.SqlBatch:
                    await HandleSqlBatchAsync(message, ct);
                    break;

                case TdsPacketType.Rpc:
                    await HandleRpcAsync(message, ct);
                    break;

                default:
                    // Attention, TransactionManagerRequest, etc. — forward transparently
                    await WriteToServerAsync(message, ct);
                    break;
            }
        }
    }

    /// <summary>
    /// Server→Client relay: reads raw TDS packets from server and forwards to client.
    /// Runs independently of the client→server direction.
    /// All server responses (result sets, errors, DONE tokens) flow through here.
    /// </summary>
    private async Task RelayServerToClientAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var packet = await _serverReader!.ReadPacketAsync(ct);
            if (packet == null)
            {
                _logger.LogDebug("Server disconnected");
                break;
            }

            await WriteToClientRawAsync(packet.RawBytes, ct);
        }
    }

    private async Task HandleSqlBatchAsync(TdsMessage message, CancellationToken ct)
    {
        var batch = new SqlBatchMessage(message);
        var sqlText = batch.GetSqlText();

        var context = BuildQueryContext(sqlText);
        var result = _ruleEngine.Evaluate(context);

        if (result.IsBlocked)
        {
            _auditLogger.LogBlocked(context, result.Reason!);
            await SendBlockedResponseAsync($"Query blocked by TailSqlProxy: {result.Reason}", ct);
            return;
        }

        _auditLogger.LogQuery(context);
        await WriteToServerAsync(message, ct);
    }

    private async Task HandleRpcAsync(TdsMessage message, CancellationToken ct)
    {
        var rpc = new RpcRequestMessage(message);
        var procName = rpc.GetProcedureName();
        var sqlText = rpc.GetSqlTextFromSpExecuteSql() ?? $"EXEC {procName}";

        var context = BuildQueryContext(sqlText, procName, isRpc: true);
        var result = _ruleEngine.Evaluate(context);

        if (result.IsBlocked)
        {
            _auditLogger.LogBlocked(context, result.Reason!);
            await SendBlockedResponseAsync($"Query blocked by TailSqlProxy: {result.Reason}", ct);
            return;
        }

        _auditLogger.LogQuery(context);
        await WriteToServerAsync(message, ct);
    }

    /// <summary>
    /// Rewrites the ServerName field in a Login7 message so Azure SQL accepts the connection.
    /// Clients connecting through the proxy send "localhost" as the server name, but Azure SQL
    /// requires its own hostname in the Login7 packet.
    /// </summary>
    private TdsMessage RewriteLogin7ServerName(TdsMessage loginMessage, string newServerName)
    {
        var payload = loginMessage.Payload;
        if (payload.Length < 56)
            return loginMessage;

        // Read ServerName pointer: offset at byte 52 (LE ushort), char length at byte 54 (LE ushort)
        ushort serverOffset = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(52));
        ushort serverCharLen = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(54));

        int oldByteLen = serverCharLen * 2;
        byte[] newServerBytes = System.Text.Encoding.Unicode.GetBytes(newServerName);
        int newByteLen = newServerBytes.Length;
        int delta = newByteLen - oldByteLen;

        if (delta == 0 && serverCharLen > 0)
        {
            // Same length — just overwrite in place
            Array.Copy(newServerBytes, 0, payload, serverOffset, newByteLen);
            return RebuildLogin7Message(payload);
        }

        // Build new payload with adjusted size
        var newPayload = new byte[payload.Length + delta];

        // Copy everything before the server name data
        Array.Copy(payload, 0, newPayload, 0, serverOffset);
        // Insert new server name
        Array.Copy(newServerBytes, 0, newPayload, serverOffset, newByteLen);
        // Copy everything after the old server name data
        int afterOld = serverOffset + oldByteLen;
        Array.Copy(payload, afterOld, newPayload, serverOffset + newByteLen, payload.Length - afterOld);

        // Update ServerName char length
        BinaryPrimitives.WriteUInt16LittleEndian(newPayload.AsSpan(54), (ushort)newServerName.Length);

        // Update total Login7 length at bytes 0-3
        uint totalLen = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(0));
        BinaryPrimitives.WriteUInt32LittleEndian(newPayload.AsSpan(0), (uint)(totalLen + delta));

        // Adjust all string/extension pointer offsets that point past the old server name position
        // Login7 pointer fields: each has a 2-byte LE offset at these positions
        int[] pointerOffsets = [36, 40, 44, 48, 52, 56, 60, 64, 68, 78, 82, 86];
        foreach (int ptrOff in pointerOffsets)
        {
            if (ptrOff + 2 > newPayload.Length) break;
            ushort dataOff = BinaryPrimitives.ReadUInt16LittleEndian(newPayload.AsSpan(ptrOff));
            if (dataOff > serverOffset)
                BinaryPrimitives.WriteUInt16LittleEndian(newPayload.AsSpan(ptrOff), (ushort)(dataOff + delta));
        }

        // Adjust the nested FeatureExt pointer inside the extension data area.
        // ibExtension (offset 56) points to extension data in the variable area.
        // The first 4 bytes at that location are a DWORD offset to the FeatureExt block.
        if (newPayload.Length > 58)
        {
            ushort ibExt = BinaryPrimitives.ReadUInt16LittleEndian(newPayload.AsSpan(56));
            if (ibExt > 0 && ibExt + 4 <= newPayload.Length)
            {
                uint featureExtOff = BinaryPrimitives.ReadUInt32LittleEndian(newPayload.AsSpan(ibExt));
                if (featureExtOff > (uint)serverOffset && featureExtOff < (uint)newPayload.Length)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(newPayload.AsSpan(ibExt),
                        (uint)(featureExtOff + delta));
                }
            }
        }

        _logger.LogDebug("Rewrote Login7 ServerName from {OldLen} chars to '{NewServer}' ({Delta:+#;-#;0} bytes)",
            serverCharLen, newServerName, delta);

        return RebuildLogin7Message(newPayload);
    }

    private static TdsMessage RebuildLogin7Message(byte[] payload)
    {
        var packetLen = (ushort)(TdsPacketHeader.Size + payload.Length);
        var raw = new byte[packetLen];
        var header = new TdsPacketHeader(
            type: TdsPacketType.Login7,
            status: (byte)TdsStatusBits.EndOfMessage,
            length: packetLen,
            spid: 0,
            packetId: 1,
            window: 0);
        header.WriteTo(raw);
        Array.Copy(payload, 0, raw, TdsPacketHeader.Size, payload.Length);
        var packet = new TdsPacket(header, payload, raw);
        return new TdsMessage(TdsPacketType.Login7, payload, new[] { packet });
    }

    private QueryContext BuildQueryContext(string sqlText, string? procName = null, bool isRpc = false)
    {
        return new QueryContext
        {
            SqlText = sqlText,
            ProcedureName = procName,
            IsRpc = isRpc,
            ClientIp = _clientIp,
            HostName = _hostName,
            Username = _username,
            Database = _database,
            AppName = _appName,
            SessionId = _sessionId,
            StartTimeUtc = DateTime.UtcNow,
        };
    }

    private async Task SendBlockedResponseAsync(string message, CancellationToken ct)
    {
        var errorPayload = TdsResponseBuilder.BuildErrorResponse(
            errorNumber: 50000,
            state: 1,
            severity: 16,
            message: message,
            serverName: "TailSqlProxy");

        await WriteToClientAsync(TdsPacketType.TabularResult, errorPayload, ct);
    }

    // --- Thread-safe write methods using locks ---

    private async Task WriteToServerAsync(TdsMessage message, CancellationToken ct)
    {
        await _serverWriteLock.WaitAsync(ct);
        try
        {
            foreach (var packet in message.Packets)
            {
                await _serverWriter!.WriteRawAsync(packet.RawBytes, ct);
            }
        }
        finally
        {
            _serverWriteLock.Release();
        }
    }

    private async Task WriteToClientRawAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        await _clientWriteLock.WaitAsync(ct);
        try
        {
            await _clientWriter!.WriteRawAsync(data, ct);
        }
        finally
        {
            _clientWriteLock.Release();
        }
    }

    private async Task WriteToClientAsync(TdsPacketType type, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        await _clientWriteLock.WaitAsync(ct);
        try
        {
            await _clientWriter!.WriteMessageAsync(type, payload, ct);
        }
        finally
        {
            _clientWriteLock.Release();
        }
    }

    // --- PreLogin and Login7 (sequential, before bidirectional relay) ---

    private async Task ForwardPreLoginAsync(CancellationToken ct)
    {
        var clientPreLogin = await _clientReader!.ReadMessageAsync(ct);
        if (clientPreLogin == null)
            throw new InvalidOperationException("Client disconnected during PreLogin.");

        _logger.LogDebug("Received PreLogin from client, forwarding to server");
        foreach (var packet in clientPreLogin.Packets)
            await _serverWriter!.WriteRawAsync(packet.RawBytes, ct);

        var serverPreLogin = await _serverReader!.ReadMessageAsync(ct);
        if (serverPreLogin == null)
            throw new InvalidOperationException("Server disconnected during PreLogin.");

        _logger.LogDebug("Received PreLogin response from server, forwarding to client");
        foreach (var packet in serverPreLogin.Packets)
            await _clientWriter!.WriteRawAsync(packet.RawBytes, ct);
    }

    private async Task HandleLogin7Async(CancellationToken ct)
    {
        var loginMessage = await _clientReader!.ReadMessageAsync(ct);
        if (loginMessage == null)
            throw new InvalidOperationException("Client disconnected during Login7.");

        bool expectFedAuth = false;

        if (loginMessage.Type == TdsPacketType.Login7)
        {
            var login = new Login7Message(loginMessage);
            _username = login.ExtractUsername();
            _database = login.ExtractDatabase();
            _appName = login.ExtractAppName();
            _hostName = login.ExtractHostName();

            var (major, minor, build) = login.ExtractTdsVersion();
            _logger.LogInformation(
                "Login7: User={Username}, DB={Database}, App={AppName}, TDS={Major}.{Minor}.{Build}",
                _username, _database, _appName, major, minor, build);

            if (login.HasFeatureExtension())
            {
                var features = login.GetRequestedFeatures();
                _logger.LogDebug("Login7 FeatureExt: {Features}",
                    string.Join(", ", features));

                expectFedAuth = login.RequestsFedAuth();
                if (expectFedAuth)
                    _logger.LogDebug("Client requests FedAuth (Azure AD/Entra ID authentication)");
            }
        }

        // Rewrite server name in Login7 to match the target server
        // (clients send "localhost" when connecting to the proxy, but Azure SQL requires its real hostname)
        loginMessage = RewriteLogin7ServerName(loginMessage, _targetOptions.Host);

        // Forward Login7 to server
        foreach (var packet in loginMessage.Packets)
            await _serverWriter!.WriteRawAsync(packet.RawBytes, ct);

        // Forward server's login response to client
        await ForwardServerResponseToClientAsync(ct);

        if (expectFedAuth)
        {
            var fedAuthMessage = await _clientReader!.ReadMessageAsync(ct);
            if (fedAuthMessage == null)
                throw new InvalidOperationException("Client disconnected during FedAuth token exchange.");

            if (fedAuthMessage.Type == TdsPacketType.FederatedAuthToken)
            {
                _logger.LogDebug("Relaying FederatedAuthToken to server (Entra ID auth)");
                foreach (var packet in fedAuthMessage.Packets)
                    await _serverWriter!.WriteRawAsync(packet.RawBytes, ct);
                await ForwardServerResponseToClientAsync(ct);
            }
            else
            {
                _logger.LogWarning("Expected FederatedAuthToken but got {Type}", fedAuthMessage.Type);
                foreach (var packet in fedAuthMessage.Packets)
                    await _serverWriter!.WriteRawAsync(packet.RawBytes, ct);
                await ForwardServerResponseToClientAsync(ct);
            }
        }
    }

    /// <summary>
    /// Sequential response forwarding used only during login handshake (before bidirectional relay).
    /// Includes a timeout to prevent hung connections.
    /// </summary>
    private async Task ForwardServerResponseToClientAsync(CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(ResponseTimeout);

        while (true)
        {
            var packet = await _serverReader!.ReadPacketAsync(timeoutCts.Token);
            if (packet == null)
            {
                _logger.LogWarning("Server disconnected during response forwarding");
                break;
            }

            await _clientWriter!.WriteRawAsync(packet.RawBytes, timeoutCts.Token);

            if (packet.Header.IsEndOfMessage && packet.Header.Type == TdsPacketType.TabularResult)
            {
                if (ContainsFinalDoneToken(packet.Payload))
                    break;
            }
        }
    }

    /// <summary>
    /// Checks if the packet payload ends with a DONE or DONEPROC token
    /// that does not have the DONE_MORE (0x0001) status bit set.
    /// </summary>
    private static bool ContainsFinalDoneToken(byte[] payload)
    {
        const int doneTokenSize = 13;

        if (payload.Length < doneTokenSize)
            return false;

        int offset = payload.Length - doneTokenSize;
        byte tokenType = payload[offset];

        if (tokenType is not (0xFD or 0xFE))
        {
            for (int i = payload.Length - doneTokenSize; i >= 0; i--)
            {
                if (payload[i] is 0xFD or 0xFE)
                {
                    offset = i;
                    tokenType = payload[i];
                    break;
                }
            }

            if (tokenType is not (0xFD or 0xFE))
                return false;
        }

        if (offset + 3 > payload.Length)
            return false;

        ushort status = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(offset + 1, 2));
        return (status & 0x0001) == 0;
    }

    public void Dispose()
    {
        _clientWriteLock.Dispose();
        _serverWriteLock.Dispose();
        _clientStream?.Dispose();
        _serverStream?.Dispose();
        _serverConnection?.Dispose();
    }
}
