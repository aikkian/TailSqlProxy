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

    // Session state
    private string? _clientIp;
    private string? _username;
    private string? _database;
    private string? _appName;

    public ClientSession(
        IOptions<TargetServerOptions> targetOptions,
        TlsBridge tlsBridge,
        IRuleEngine ruleEngine,
        IAuditLogger auditLogger,
        ILogger<ClientSession> logger)
    {
        _targetOptions = targetOptions.Value;
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

            _auditLogger.LogConnection(_clientIp, _username, _database, _appName);

            // 6. Main message loop
            await MessageLoopAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Session error for client {ClientIp}", _clientIp);
        }
        finally
        {
            _auditLogger.LogDisconnection(_clientIp, _username);
            _logger.LogInformation("Client {ClientIp} disconnected (User={Username})", _clientIp, _username);
        }
    }

    private async Task ForwardPreLoginAsync(CancellationToken ct)
    {
        // Forward client's PreLogin to server
        var clientPreLogin = await _clientReader!.ReadMessageAsync(ct);
        if (clientPreLogin == null)
            throw new InvalidOperationException("Client disconnected during PreLogin.");

        _logger.LogDebug("Received PreLogin from client, forwarding to server");
        await ForwardToServerRawAsync(clientPreLogin, ct);

        // Forward server's PreLogin response to client
        var serverPreLogin = await _serverReader!.ReadMessageAsync(ct);
        if (serverPreLogin == null)
            throw new InvalidOperationException("Server disconnected during PreLogin.");

        _logger.LogDebug("Received PreLogin response from server, forwarding to client");
        await ForwardToClientRawAsync(serverPreLogin, ct);
    }

    private async Task HandleLogin7Async(CancellationToken ct)
    {
        var loginMessage = await _clientReader!.ReadMessageAsync(ct);
        if (loginMessage == null)
            throw new InvalidOperationException("Client disconnected during Login7.");

        if (loginMessage.Type == TdsPacketType.Login7)
        {
            var login = new Login7Message(loginMessage);
            _username = login.ExtractUsername();
            _database = login.ExtractDatabase();
            _appName = login.ExtractAppName();
            _logger.LogInformation("Login7: User={Username}, DB={Database}, App={AppName}", _username, _database, _appName);
        }

        // Forward Login7 to server
        await ForwardToServerRawAsync(loginMessage, ct);

        // Forward server's login response to client
        // The server may send multiple response messages (LOGINACK, ENVCHANGE, etc.)
        await ForwardServerResponseToClientAsync(ct);
    }

    private async Task MessageLoopAsync(CancellationToken ct)
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

                case TdsPacketType.Attention:
                    await ForwardToServerRawAsync(message, ct);
                    await ForwardServerResponseToClientAsync(ct);
                    break;

                default:
                    await ForwardToServerRawAsync(message, ct);
                    await ForwardServerResponseToClientAsync(ct);
                    break;
            }
        }
    }

    private async Task HandleSqlBatchAsync(TdsMessage message, CancellationToken ct)
    {
        var batch = new SqlBatchMessage(message);
        var sqlText = batch.GetSqlText();

        var context = new QueryContext
        {
            SqlText = sqlText,
            ClientIp = _clientIp,
            Username = _username,
            Database = _database,
            AppName = _appName,
        };

        var result = _ruleEngine.Evaluate(context);

        if (result.IsBlocked)
        {
            _auditLogger.LogBlocked(context, result.Reason!);
            await SendBlockedResponseAsync($"Query blocked by TailSqlProxy: {result.Reason}", ct);
            return;
        }

        _auditLogger.LogQuery(context);
        await ForwardToServerRawAsync(message, ct);
        await ForwardServerResponseToClientAsync(ct);
    }

    private async Task HandleRpcAsync(TdsMessage message, CancellationToken ct)
    {
        var rpc = new RpcRequestMessage(message);
        var procName = rpc.GetProcedureName();
        var sqlText = rpc.GetSqlTextFromSpExecuteSql() ?? $"EXEC {procName}";

        var context = new QueryContext
        {
            SqlText = sqlText,
            ProcedureName = procName,
            IsRpc = true,
            ClientIp = _clientIp,
            Username = _username,
            Database = _database,
            AppName = _appName,
        };

        var result = _ruleEngine.Evaluate(context);

        if (result.IsBlocked)
        {
            _auditLogger.LogBlocked(context, result.Reason!);
            await SendBlockedResponseAsync($"Query blocked by TailSqlProxy: {result.Reason}", ct);
            return;
        }

        _auditLogger.LogQuery(context);
        await ForwardToServerRawAsync(message, ct);
        await ForwardServerResponseToClientAsync(ct);
    }

    private async Task SendBlockedResponseAsync(string message, CancellationToken ct)
    {
        var errorPayload = TdsResponseBuilder.BuildErrorResponse(
            errorNumber: 50000,
            state: 1,
            severity: 16,
            message: message,
            serverName: "TailSqlProxy");

        await _clientWriter!.WriteMessageAsync(TdsPacketType.TabularResult, errorPayload, ct);
    }

    private async Task ForwardToServerRawAsync(TdsMessage message, CancellationToken ct)
    {
        foreach (var packet in message.Packets)
        {
            await _serverWriter!.WriteRawAsync(packet.RawBytes, ct);
        }
    }

    private async Task ForwardToClientRawAsync(TdsMessage message, CancellationToken ct)
    {
        foreach (var packet in message.Packets)
        {
            await _clientWriter!.WriteRawAsync(packet.RawBytes, ct);
        }
    }

    private async Task ForwardServerResponseToClientAsync(CancellationToken ct)
    {
        // Read packets from server and forward to client.
        // Response ends when we detect a final DONE/DONEPROC token (without DONE_MORE bit).
        while (true)
        {
            var packet = await _serverReader!.ReadPacketAsync(ct);
            if (packet == null)
            {
                _logger.LogWarning("Server disconnected during response forwarding");
                break;
            }

            await _clientWriter!.WriteRawAsync(packet.RawBytes, ct);

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
    /// DONE token: 0xFD (12 bytes: token(1) + status(2) + curcmd(2) + rowcount(8) = 13 total)
    /// DONEPROC token: 0xFE (same structure)
    /// </summary>
    private static bool ContainsFinalDoneToken(byte[] payload)
    {
        // DONE/DONEPROC/DONEINPROC tokens are 13 bytes each (1 + 2 + 2 + 8)
        const int doneTokenSize = 13;

        if (payload.Length < doneTokenSize)
            return false;

        // Check last potential token
        int offset = payload.Length - doneTokenSize;
        byte tokenType = payload[offset];

        if (tokenType is not (0xFD or 0xFE))
        {
            // Try checking at different offsets in case there are trailing bytes
            // or multiple DONE tokens
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

        // DONE_MORE = 0x0001: if NOT set, this is the final response
        return (status & 0x0001) == 0;
    }

    public void Dispose()
    {
        _clientStream?.Dispose();
        _serverStream?.Dispose();
        _serverConnection?.Dispose();
    }
}
