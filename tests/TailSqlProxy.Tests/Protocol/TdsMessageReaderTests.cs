using System.Buffers.Binary;
using FluentAssertions;
using TailSqlProxy.Protocol;
using Xunit;

namespace TailSqlProxy.Tests.Protocol;

public class TdsMessageReaderTests
{
    [Fact]
    public async Task ReadPacketAsync_SinglePacket_ReturnsCorrectly()
    {
        var payload = new byte[] { 0x41, 0x42, 0x43, 0x44 }; // "ABCD"
        var packet = BuildRawPacket(TdsPacketType.SqlBatch, 0x01, payload);

        using var stream = new MemoryStream(packet);
        var reader = new TdsMessageReader(stream);

        var result = await reader.ReadPacketAsync();

        result.Should().NotBeNull();
        result!.Header.Type.Should().Be(TdsPacketType.SqlBatch);
        result.Header.IsEndOfMessage.Should().BeTrue();
        result.Payload.Should().BeEquivalentTo(payload);
        result.RawBytes.Length.Should().Be(TdsPacketHeader.Size + payload.Length);
    }

    [Fact]
    public async Task ReadPacketAsync_EmptyStream_ReturnsNull()
    {
        using var stream = new MemoryStream([]);
        var reader = new TdsMessageReader(stream);

        var result = await reader.ReadPacketAsync();

        result.Should().BeNull();
    }

    [Fact]
    public async Task ReadMessageAsync_SinglePacketMessage_ReturnsAssembled()
    {
        var payload = new byte[] { 0x01, 0x02, 0x03 };
        var packet = BuildRawPacket(TdsPacketType.SqlBatch, 0x01, payload);

        using var stream = new MemoryStream(packet);
        var reader = new TdsMessageReader(stream);

        var message = await reader.ReadMessageAsync();

        message.Should().NotBeNull();
        message!.Type.Should().Be(TdsPacketType.SqlBatch);
        message.Payload.Should().BeEquivalentTo(payload);
        message.Packets.Should().HaveCount(1);
    }

    [Fact]
    public async Task ReadMessageAsync_MultiPacketMessage_ReassemblesCorrectly()
    {
        var payload1 = new byte[] { 0x01, 0x02, 0x03 };
        var payload2 = new byte[] { 0x04, 0x05, 0x06 };
        var payload3 = new byte[] { 0x07, 0x08 };

        var packet1 = BuildRawPacket(TdsPacketType.SqlBatch, 0x00, payload1); // Not EOM
        var packet2 = BuildRawPacket(TdsPacketType.SqlBatch, 0x00, payload2); // Not EOM
        var packet3 = BuildRawPacket(TdsPacketType.SqlBatch, 0x01, payload3); // EOM

        var combined = packet1.Concat(packet2).Concat(packet3).ToArray();
        using var stream = new MemoryStream(combined);
        var reader = new TdsMessageReader(stream);

        var message = await reader.ReadMessageAsync();

        message.Should().NotBeNull();
        message!.Type.Should().Be(TdsPacketType.SqlBatch);
        message.Payload.Should().BeEquivalentTo([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        message.Packets.Should().HaveCount(3);
    }

    [Fact]
    public async Task ReadMessageAsync_EmptyStream_ReturnsNull()
    {
        using var stream = new MemoryStream([]);
        var reader = new TdsMessageReader(stream);

        var message = await reader.ReadMessageAsync();

        message.Should().BeNull();
    }

    private static byte[] BuildRawPacket(TdsPacketType type, byte status, byte[] payload)
    {
        var raw = new byte[TdsPacketHeader.Size + payload.Length];
        raw[0] = (byte)type;
        raw[1] = status;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2), (ushort)(TdsPacketHeader.Size + payload.Length));
        raw[4] = 0; // SPID high
        raw[5] = 0; // SPID low
        raw[6] = 1; // PacketID
        raw[7] = 0; // Window
        Array.Copy(payload, 0, raw, TdsPacketHeader.Size, payload.Length);
        return raw;
    }
}
