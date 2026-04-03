using System.Buffers.Binary;

namespace TailSqlProxy.Protocol.Messages;

public class PreLoginMessage
{
    public enum PreLoginTokenType : byte
    {
        Version = 0x00,
        Encryption = 0x01,
        InstOpt = 0x02,
        ThreadId = 0x03,
        Mars = 0x04,
        TraceId = 0x05,
        FedAuthRequired = 0x06,
        NonceOpt = 0x07,
        Terminator = 0xFF,
    }

    public enum EncryptionOption : byte
    {
        Off = 0x00,
        On = 0x01,
        NotSupported = 0x02,
        Required = 0x03,
    }

    private readonly byte[] _payload;

    public PreLoginMessage(byte[] payload)
    {
        _payload = payload;
    }

    public PreLoginMessage(TdsMessage message)
    {
        _payload = message.Payload;
    }

    public EncryptionOption? GetEncryptionOption()
    {
        var tokens = ParseTokens();
        if (tokens.TryGetValue(PreLoginTokenType.Encryption, out var data) && data.Length >= 1)
            return (EncryptionOption)data[0];
        return null;
    }

    public byte[] SetEncryptionOption(EncryptionOption option)
    {
        var result = (byte[])_payload.Clone();
        var span = result.AsSpan();
        int offset = 0;

        while (offset < span.Length)
        {
            byte tokenType = span[offset];
            if (tokenType == (byte)PreLoginTokenType.Terminator)
                break;

            if (offset + 5 > span.Length)
                break;

            ushort dataOffset = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 1)..]);
            ushort dataLength = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 3)..]);

            if (tokenType == (byte)PreLoginTokenType.Encryption && dataLength >= 1)
            {
                result[dataOffset] = (byte)option;
            }

            offset += 5;
        }

        return result;
    }

    private Dictionary<PreLoginTokenType, byte[]> ParseTokens()
    {
        var tokens = new Dictionary<PreLoginTokenType, byte[]>();
        var span = _payload.AsSpan();
        int offset = 0;

        while (offset < span.Length)
        {
            byte tokenType = span[offset];
            if (tokenType == (byte)PreLoginTokenType.Terminator)
                break;

            if (offset + 5 > span.Length)
                break;

            ushort dataOffset = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 1)..]);
            ushort dataLength = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 3)..]);

            if (dataOffset + dataLength <= span.Length)
            {
                tokens[(PreLoginTokenType)tokenType] = span.Slice(dataOffset, dataLength).ToArray();
            }

            offset += 5;
        }

        return tokens;
    }
}
