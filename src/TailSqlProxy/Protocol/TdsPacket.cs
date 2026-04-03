namespace TailSqlProxy.Protocol;

public class TdsPacket
{
    public TdsPacketHeader Header { get; }
    public byte[] Payload { get; }

    public byte[] RawBytes { get; }

    public TdsPacket(TdsPacketHeader header, byte[] payload, byte[] rawBytes)
    {
        Header = header;
        Payload = payload;
        RawBytes = rawBytes;
    }
}
