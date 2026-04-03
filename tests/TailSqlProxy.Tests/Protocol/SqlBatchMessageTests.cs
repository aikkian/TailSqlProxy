using System.Buffers.Binary;
using System.Text;
using FluentAssertions;
using TailSqlProxy.Protocol.Messages;
using Xunit;

namespace TailSqlProxy.Tests.Protocol;

public class SqlBatchMessageTests
{
    [Fact]
    public void GetSqlText_WithAllHeaders_ExtractsCorrectly()
    {
        var sqlText = "SELECT * FROM Orders";
        var payload = BuildSqlBatchPayload(sqlText);

        var message = new SqlBatchMessage(payload);
        var result = message.GetSqlText();

        result.Should().Be(sqlText);
    }

    [Fact]
    public void GetSqlText_SimpleSelect_Works()
    {
        var sqlText = "SELECT TOP 10 * FROM Products WHERE Price > 100";
        var payload = BuildSqlBatchPayload(sqlText);

        var message = new SqlBatchMessage(payload);
        var result = message.GetSqlText();

        result.Should().Be(sqlText);
    }

    [Fact]
    public void GetSqlText_UnicodeCharacters_Works()
    {
        var sqlText = "SELECT * FROM Users WHERE Name = N'日本語テスト'";
        var payload = BuildSqlBatchPayload(sqlText);

        var message = new SqlBatchMessage(payload);
        var result = message.GetSqlText();

        result.Should().Be(sqlText);
    }

    [Fact]
    public void GetSqlText_EmptyPayload_ReturnsEmpty()
    {
        var payload = new byte[0];
        var message = new SqlBatchMessage(payload);
        var result = message.GetSqlText();

        result.Should().BeEmpty();
    }

    [Fact]
    public void GetSqlText_MultiStatement_Works()
    {
        var sqlText = "SELECT 1; SELECT 2; SELECT 3;";
        var payload = BuildSqlBatchPayload(sqlText);

        var message = new SqlBatchMessage(payload);
        var result = message.GetSqlText();

        result.Should().Be(sqlText);
    }

    /// <summary>
    /// Builds a SQL Batch payload with a minimal ALL_HEADERS section.
    /// ALL_HEADERS: first 4 bytes = total length of ALL_HEADERS (including the 4-byte length field).
    /// Minimum ALL_HEADERS = just the length field = 4 bytes (no actual headers).
    /// </summary>
    private static byte[] BuildSqlBatchPayload(string sqlText)
    {
        var sqlBytes = Encoding.Unicode.GetBytes(sqlText);

        // Minimal ALL_HEADERS: TotalLength (4 bytes) + one header
        // A basic transaction descriptor header is 18 bytes:
        //   HeaderLength(4) + HeaderType(2) + TransactionDescriptor(8) + OutstandingRequestCount(4)
        int headerLength = 4 + 18; // 22 bytes
        var payload = new byte[headerLength + sqlBytes.Length];

        // ALL_HEADERS TotalLength
        BinaryPrimitives.WriteInt32LittleEndian(payload, headerLength);

        // Transaction descriptor header
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(4), 18); // This header's length
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(8), 2); // Type: Transaction descriptor
        // TransactionDescriptor (8 bytes) = 0
        // OutstandingRequestCount (4 bytes) = 1
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(18), 1);

        // SQL text follows ALL_HEADERS
        Array.Copy(sqlBytes, 0, payload, headerLength, sqlBytes.Length);

        return payload;
    }
}
