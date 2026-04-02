using System.Buffers.Binary;

namespace TailSqlProxy.Protocol;

public class TdsMessageWriter
{
    private readonly Stream _stream;
    private readonly int _maxPacketSize;

    public TdsMessageWriter(Stream stream, int maxPacketSize = 4096)
    {
        _stream = stream;
        _maxPacketSize = maxPacketSize;
    }

    public async Task WriteRawAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        await _stream.WriteAsync(data, ct);
        await _stream.FlushAsync(ct);
    }

    public async Task WriteMessageAsync(TdsPacketType type, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        int maxPayloadPerPacket = _maxPacketSize - TdsPacketHeader.Size;
        int offset = 0;
        byte packetId = 1;

        while (offset < payload.Length || offset == 0)
        {
            int chunkSize = Math.Min(maxPayloadPerPacket, payload.Length - offset);
            bool isLast = (offset + chunkSize) >= payload.Length;
            ushort packetLength = (ushort)(TdsPacketHeader.Size + chunkSize);

            var header = new TdsPacketHeader(
                type: type,
                status: isLast ? (byte)TdsStatusBits.EndOfMessage : (byte)TdsStatusBits.Normal,
                length: packetLength,
                spid: 0,
                packetId: packetId,
                window: 0
            );

            var packetBytes = new byte[packetLength];
            header.WriteTo(packetBytes);
            payload.Slice(offset, chunkSize).CopyTo(packetBytes.AsMemory(TdsPacketHeader.Size));

            await _stream.WriteAsync(packetBytes.AsMemory(), ct);

            offset += chunkSize;
            packetId++;

            if (chunkSize == 0) break;
        }

        await _stream.FlushAsync(ct);
    }
}
