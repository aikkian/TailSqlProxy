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
            // 1. Connect to target Azure SQL
            _serverConnection = new TcpClient();
            await _serverConnection.ConnectAsync(_targetOptions.Host, _targetOptions.Port, ct);
            _logger.LogDebug("Connected to target server {Host}:{Port}", _targetOptions.Host, _targetOptions.Port);

            // 2. Establish TLS on both sides (TDS 8.0 mode for Azure SQL)
            var (clientSsl, serverSsl) = await _tlsBridge.EstablishTds8TlsAsync(
                client.GetStream(),
                _serverConnection.GetStream(),
                _targetOptions.Host,
                ct);

            _clientStream = clientSsl;
            _serverStream = serverSsl;

            // 3. Create readers/writers
            _clientReader = new TdsMessageReader(_clientStream);
            _clientWriter = new TdsMessageWriter(_clientStream);
            _serverReader = new TdsMessageReader(_serverStream);
            _serverWriter = new TdsMessageWriter(_serverStream);

            // 4. Handle PreLogin exchange
            await ForwardPreLoginAsync(ct);

            // 5. Handle Login7 (extract user/db info, then forward)
            await HandleLogin7Async(ct);

            _auditLogger.LogConnection(_clientIp, _username, _database, _appName, _sessionId);

            // 6. Bidirectional relay — two concurrent tasks for MARS support
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
