using System.Buffers.Binary;
using System.Text;

namespace TailSqlProxy.Protocol.Messages;

public static class TdsResponseBuilder
{
    /// <summary>
    /// Builds a TDS error response (ERROR token + DONE token) to send to the client.
    /// This creates a valid TabularResult payload that clients like SSMS will display as an error.
    /// </summary>
    public static byte[] BuildErrorResponse(
        int errorNumber,
        byte state,
        byte severity,
        string message,
        string serverName = "TailSqlProxy",
        string procName = "",
        int lineNumber = 1)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.Unicode, leaveOpen: true);

        // ERROR token (0xAA)
        WriteErrorToken(writer, errorNumber, state, severity, message, serverName, procName, lineNumber);

        // DONE token (0xFD) with ERROR status
        WriteDoneToken(writer, isDoneError: true, rowCount: 0);

        return ms.ToArray();
    }

    private static void WriteErrorToken(
        BinaryWriter writer,
        int errorNumber,
        byte state,
        byte severity,
        string message,
        string serverName,
        string procName,
        int lineNumber)
    {
        var tokenData = BuildErrorTokenData(errorNumber, state, severity, message, serverName, procName, lineNumber);

        writer.Write((byte)0xAA); // ERROR token type
        writer.Write((ushort)tokenData.Length); // Length (little-endian, auto by BinaryWriter)
        writer.Write(tokenData);
    }

    private static byte[] BuildErrorTokenData(
        int errorNumber,
        byte state,
        byte severity,
        string message,
        string serverName,
        string procName,
        int lineNumber)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.Unicode, leaveOpen: true);

        // Error number (4 bytes, INT32)
        w.Write(errorNumber);

        // State (1 byte)
        w.Write(state);

        // Class/Severity (1 byte)
        w.Write(severity);

        // Message text (US_VARCHAR: 2-byte char count + UTF-16LE text)
        var msgBytes = Encoding.Unicode.GetBytes(message);
        w.Write((ushort)(msgBytes.Length / 2));
        w.Write(msgBytes);

        // Server name (B_VARCHAR: 1-byte char count + UTF-16LE text)
        var serverBytes = Encoding.Unicode.GetBytes(serverName);
        w.Write((byte)(serverBytes.Length / 2));
        w.Write(serverBytes);

        // Procedure name (B_VARCHAR: 1-byte char count + UTF-16LE text)
        var procBytes = Encoding.Unicode.GetBytes(procName);
        w.Write((byte)(procBytes.Length / 2));
        w.Write(procBytes);

        // Line number (4 bytes, INT32)
        w.Write(lineNumber);

        return ms.ToArray();
    }

    private static void WriteDoneToken(BinaryWriter writer, bool isDoneError, long rowCount)
    {
        writer.Write((byte)0xFD); // DONE token type

        // Status (2 bytes): 0x0002 = DONE_ERROR if error
        ushort status = isDoneError ? (ushort)0x0002 : (ushort)0x0000;
        writer.Write(status);

        // CurCmd (2 bytes): 0 for generic
        writer.Write((ushort)0);

        // RowCount (8 bytes for TDS 7.2+)
        writer.Write(rowCount);
    }
}
