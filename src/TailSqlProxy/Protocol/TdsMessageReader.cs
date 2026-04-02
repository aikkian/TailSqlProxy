namespace TailSqlProxy.Protocol;

public class TdsMessageReader
{
    private readonly Stream _stream;
    private readonly byte[] _headerBuffer = new byte[TdsPacketHeader.Size];

    public TdsMessageReader(Stream stream)
    {
        _stream = stream;
    }

    public async Task<TdsPacket?> ReadPacketAsync(CancellationToken ct = default)
    {
        int bytesRead = await ReadExactAsync(_stream, _headerBuffer, 0, TdsPacketHeader.Size, ct);
        if (bytesRead == 0)
            return null;

        if (bytesRead < TdsPacketHeader.Size)
            throw new InvalidOperationException("Incomplete TDS packet header received.");

        var header = new TdsPacketHeader(_headerBuffer);
        int payloadLength = header.PayloadLength;

        if (payloadLength < 0)
            throw new InvalidOperationException($"Invalid TDS packet length: {header.Length}");

        var payload = new byte[payloadLength];
        if (payloadLength > 0)
        {
            bytesRead = await ReadExactAsync(_stream, payload, 0, payloadLength, ct);
            if (bytesRead < payloadLength)
                throw new InvalidOperationException("Incomplete TDS packet payload received.");
        }

        var raw = new byte[TdsPacketHeader.Size + payloadLength];
        Array.Copy(_headerBuffer, 0, raw, 0, TdsPacketHeader.Size);
        Array.Copy(payload, 0, raw, TdsPacketHeader.Size, payloadLength);

        return new TdsPacket(header, payload, raw);
    }

    public async Task<TdsMessage?> ReadMessageAsync(CancellationToken ct = default)
    {
        var firstPacket = await ReadPacketAsync(ct);
        if (firstPacket == null)
            return null;

        if (firstPacket.Header.IsEndOfMessage)
        {
            return new TdsMessage(firstPacket.Header.Type, firstPacket.Payload, new[] { firstPacket });
        }

        var packets = new List<TdsPacket> { firstPacket };
        using var payloadStream = new MemoryStream();
        payloadStream.Write(firstPacket.Payload);

        while (true)
        {
            var packet = await ReadPacketAsync(ct);
            if (packet == null)
                throw new InvalidOperationException("Connection closed during multi-packet TDS message.");

            packets.Add(packet);
            payloadStream.Write(packet.Payload);

            if (packet.Header.IsEndOfMessage)
                break;
        }

        return new TdsMessage(firstPacket.Header.Type, payloadStream.ToArray(), packets.ToArray());
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset + totalRead, count - totalRead), ct);
            if (read == 0)
            {
                if (totalRead == 0)
                    return 0;
                break;
            }
            totalRead += read;
        }
        return totalRead;
    }
}

public class TdsMessage
{
    public TdsPacketType Type { get; }
    public byte[] Payload { get; }
    public TdsPacket[] Packets { get; }

    public TdsMessage(TdsPacketType type, byte[] payload, TdsPacket[] packets)
    {
        Type = type;
        Payload = payload;
        Packets = packets;
    }
}
