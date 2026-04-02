using System.Buffers.Binary;

namespace TailSqlProxy.Protocol;

public readonly struct TdsPacketHeader
{
    public const int Size = 8;

    public TdsPacketType Type { get; }
    public byte Status { get; }
    public ushort Length { get; }
    public ushort Spid { get; }
    public byte PacketId { get; }
    public byte Window { get; }

    public bool IsEndOfMessage => (Status & (byte)TdsStatusBits.EndOfMessage) != 0;
    public int PayloadLength => Length - Size;

    public TdsPacketHeader(TdsPacketType type, byte status, ushort length, ushort spid, byte packetId, byte window)
    {
        Type = type;
        Status = status;
        Length = length;
        Spid = spid;
        PacketId = packetId;
        Window = window;
    }

    public TdsPacketHeader(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new ArgumentException($"Buffer must be at least {Size} bytes.", nameof(buffer));

        Type = (TdsPacketType)buffer[0];
        Status = buffer[1];
        Length = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..]);
        Spid = BinaryPrimitives.ReadUInt16BigEndian(buffer[4..]);
        PacketId = buffer[6];
        Window = buffer[7];
    }

    public void WriteTo(Span<byte> buffer)
    {
        if (buffer.Length < Size)
            throw new ArgumentException($"Buffer must be at least {Size} bytes.", nameof(buffer));

        buffer[0] = (byte)Type;
        buffer[1] = Status;
        BinaryPrimitives.WriteUInt16BigEndian(buffer[2..], Length);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[4..], Spid);
        buffer[6] = PacketId;
        buffer[7] = Window;
    }

    public byte[] ToBytes()
    {
        var buffer = new byte[Size];
        WriteTo(buffer);
        return buffer;
    }
}
