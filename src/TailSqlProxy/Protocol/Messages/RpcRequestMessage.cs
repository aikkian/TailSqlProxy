using System.Buffers.Binary;
using System.Text;

namespace TailSqlProxy.Protocol.Messages;

public class RpcRequestMessage
{
    private static readonly Dictionary<ushort, string> WellKnownProcIds = new()
    {
        { 1, "sp_cursor" },
        { 2, "sp_cursoropen" },
        { 3, "sp_cursorprepare" },
        { 4, "sp_cursorexecute" },
        { 5, "sp_cursorprepexec" },
        { 6, "sp_cursorunprepare" },
        { 7, "sp_cursorfetch" },
        { 8, "sp_cursoroption" },
        { 9, "sp_cursorclose" },
        { 10, "sp_executesql" },
        { 11, "sp_prepare" },
        { 12, "sp_execute" },
        { 13, "sp_prepexec" },
        { 14, "sp_prepexecrpc" },
        { 15, "sp_unprepare" },
    };

    private readonly byte[] _payload;

    public RpcRequestMessage(TdsMessage message)
    {
        if (message.Type != TdsPacketType.Rpc)
            throw new ArgumentException("Message is not an RPC request.", nameof(message));
        _payload = message.Payload;
    }

    public RpcRequestMessage(byte[] payload)
    {
        _payload = payload;
    }

    public string? GetProcedureName()
    {
        try
        {
            return GetProcedureNameInternal(out _);
        }
        catch
        {
            return null;
        }
    }

    private string? GetProcedureNameInternal(out int offsetAfterName)
    {
        var span = _payload.AsSpan();
        if (span.Length < 4)
        {
            offsetAfterName = 0;
            return null;
        }

        // Skip ALL_HEADERS
        int allHeadersLength = BinaryPrimitives.ReadInt32LittleEndian(span);
        if (allHeadersLength < 4 || allHeadersLength > span.Length)
        {
            offsetAfterName = 0;
            return null;
        }

        int offset = allHeadersLength;

        if (offset + 2 > span.Length)
        {
            offsetAfterName = offset;
            return null;
        }

        ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]);
        offset += 2;

        if (nameLen == 0xFFFF)
        {
            // Well-known procedure ID
            if (offset + 2 > span.Length)
            {
                offsetAfterName = offset;
                return null;
            }
            ushort procId = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]);
            offset += 2;
            offsetAfterName = offset;
            return WellKnownProcIds.GetValueOrDefault(procId, $"proc_id_{procId}");
        }
        else
        {
            // Named procedure
            int nameByteLen = nameLen * 2;
            if (offset + nameByteLen > span.Length)
            {
                offsetAfterName = offset;
                return null;
            }
            var name = Encoding.Unicode.GetString(span.Slice(offset, nameByteLen));
            offset += nameByteLen;
            offsetAfterName = offset;
            return name;
        }
    }

    /// <summary>
    /// For sp_executesql calls, extracts the SQL text from the first NVARCHAR parameter.
    /// </summary>
    public string? GetSqlTextFromSpExecuteSql()
    {
        try
        {
            var procName = GetProcedureNameInternal(out int offset);
            if (procName == null || !procName.Equals("sp_executesql", StringComparison.OrdinalIgnoreCase))
                return null;

            var span = _payload.AsSpan();

            // Skip OptionFlags (2 bytes)
            if (offset + 2 > span.Length)
                return null;
            offset += 2;

            // Now we're at the first parameter
            // Parameter format: NameLength(1 byte), Name(variable), StatusFlags(1), TypeInfo(variable), Value(variable)

            // Parameter name length (in Unicode chars, 0 = unnamed)
            if (offset >= span.Length)
                return null;
            byte paramNameLen = span[offset];
            offset += 1;

            // Skip parameter name
            offset += paramNameLen * 2;

            // Status flags (1 byte)
            if (offset >= span.Length)
                return null;
            offset += 1;

            // TYPE_INFO for NVARCHAR/NTEXT
            // For NVARCHAR(MAX): type = 0xE7, then maxlen (2 or 4 bytes), collation (5 bytes)
            if (offset >= span.Length)
                return null;
            byte typeId = span[offset];
            offset += 1;

            if (typeId == 0xE7) // NVARCHAR
            {
                // MaxLength (2 bytes)
                if (offset + 2 > span.Length) return null;
                ushort maxLen = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]);
                offset += 2;

                // Collation (5 bytes)
                if (offset + 5 > span.Length) return null;
                offset += 5;

                if (maxLen == 0xFFFF)
                {
                    // NVARCHAR(MAX) - uses PLP (Partially Length-Prefixed) format
                    // Total length (8 bytes)
                    if (offset + 8 > span.Length) return null;
                    long totalLen = BinaryPrimitives.ReadInt64LittleEndian(span[offset..]);
                    offset += 8;

                    if (totalLen <= 0) return null;

                    // Read PLP chunks
                    using var ms = new MemoryStream();
                    while (offset + 4 <= span.Length)
                    {
                        int chunkLen = BinaryPrimitives.ReadInt32LittleEndian(span[offset..]);
                        offset += 4;
                        if (chunkLen == 0) break; // terminator
                        if (offset + chunkLen > span.Length) break;
                        ms.Write(span.Slice(offset, chunkLen));
                        offset += chunkLen;
                    }
                    return Encoding.Unicode.GetString(ms.ToArray());
                }
                else
                {
                    // Regular NVARCHAR - actual length follows (2 bytes)
                    if (offset + 2 > span.Length) return null;
                    ushort actualLen = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]);
                    offset += 2;

                    if (actualLen == 0xFFFF) return null; // NULL value
                    if (offset + actualLen > span.Length) return null;

                    return Encoding.Unicode.GetString(span.Slice(offset, actualLen));
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }
}
