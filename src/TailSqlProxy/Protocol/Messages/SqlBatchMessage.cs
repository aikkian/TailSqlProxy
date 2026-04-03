using System.Buffers.Binary;
using System.Text;

namespace TailSqlProxy.Protocol.Messages;

public class SqlBatchMessage
{
    private readonly byte[] _payload;

    public SqlBatchMessage(TdsMessage message)
    {
        if (message.Type != TdsPacketType.SqlBatch)
            throw new ArgumentException("Message is not a SQL Batch.", nameof(message));
        _payload = message.Payload;
    }

    public SqlBatchMessage(byte[] payload)
    {
        _payload = payload;
    }

    public string GetSqlText()
    {
        var span = _payload.AsSpan();

        if (span.Length < 4)
            return string.Empty;

        // ALL_HEADERS: first 4 bytes (little-endian) = total length of ALL_HEADERS section
        int allHeadersLength = BinaryPrimitives.ReadInt32LittleEndian(span);

        // Validate: allHeadersLength should be >= 4 (at minimum, just the length field itself)
        // and should not exceed the payload
        if (allHeadersLength < 4 || allHeadersLength > span.Length)
        {
            // Possibly no ALL_HEADERS; treat entire payload as SQL text
            return Encoding.Unicode.GetString(span);
        }

        int sqlOffset = allHeadersLength;
        if (sqlOffset >= span.Length)
            return string.Empty;

        return Encoding.Unicode.GetString(span[sqlOffset..]);
    }
}
