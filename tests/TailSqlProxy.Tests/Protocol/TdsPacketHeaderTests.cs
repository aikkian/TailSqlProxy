using FluentAssertions;
using TailSqlProxy.Protocol;
using Xunit;

namespace TailSqlProxy.Tests.Protocol;

public class TdsPacketHeaderTests
{
    [Fact]
    public void Parse_SqlBatchPacket_CorrectFields()
    {
        // Type=SqlBatch(0x01), Status=EOM(0x01), Length=0x0020(32), SPID=0x0000, PacketID=1, Window=0
        byte[] header = [0x01, 0x01, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00];

        var parsed = new TdsPacketHeader(header);

        parsed.Type.Should().Be(TdsPacketType.SqlBatch);
        parsed.Status.Should().Be(0x01);
        parsed.IsEndOfMessage.Should().BeTrue();
        parsed.Length.Should().Be(32);
        parsed.PayloadLength.Should().Be(24); // 32 - 8
        parsed.Spid.Should().Be(0);
        parsed.PacketId.Should().Be(1);
        parsed.Window.Should().Be(0);
    }

    [Fact]
    public void Parse_PreLoginPacket_NotEom()
    {
        // Type=PreLogin(0x12), Status=Normal(0x00), Length=0x0100(256), SPID=0x1234, PacketID=5, Window=0
        byte[] header = [0x12, 0x00, 0x01, 0x00, 0x12, 0x34, 0x05, 0x00];

        var parsed = new TdsPacketHeader(header);

        parsed.Type.Should().Be(TdsPacketType.PreLogin);
        parsed.IsEndOfMessage.Should().BeFalse();
        parsed.Length.Should().Be(256);
        parsed.PayloadLength.Should().Be(248);
        parsed.Spid.Should().Be(0x1234);
        parsed.PacketId.Should().Be(5);
    }

    [Fact]
    public void Parse_Login7Packet()
    {
        byte[] header = [0x10, 0x01, 0x00, 0x5A, 0x00, 0x00, 0x01, 0x00];

        var parsed = new TdsPacketHeader(header);

        parsed.Type.Should().Be(TdsPacketType.Login7);
        parsed.IsEndOfMessage.Should().BeTrue();
        parsed.Length.Should().Be(90);
    }

    [Fact]
    public void Parse_RpcPacket()
    {
        byte[] header = [0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00];

        var parsed = new TdsPacketHeader(header);

        parsed.Type.Should().Be(TdsPacketType.Rpc);
        parsed.Length.Should().Be(512);
        parsed.PayloadLength.Should().Be(504);
    }

    [Fact]
    public void WriteTo_RoundTrip()
    {
        var original = new TdsPacketHeader(
            type: TdsPacketType.SqlBatch,
            status: 0x01,
            length: 100,
            spid: 0x5678,
            packetId: 3,
            window: 0);

        var buffer = new byte[8];
        original.WriteTo(buffer);
        var parsed = new TdsPacketHeader(buffer);

        parsed.Type.Should().Be(original.Type);
        parsed.Status.Should().Be(original.Status);
        parsed.Length.Should().Be(original.Length);
        parsed.Spid.Should().Be(original.Spid);
        parsed.PacketId.Should().Be(original.PacketId);
        parsed.Window.Should().Be(original.Window);
    }

    [Fact]
    public void Parse_BufferTooSmall_Throws()
    {
        byte[] buffer = [0x01, 0x01, 0x00];

        Action act = () => new TdsPacketHeader(buffer);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void BigEndian_Length_Verified()
    {
        // Length = 0x0308 = 776 in big-endian
        byte[] header = [0x04, 0x01, 0x03, 0x08, 0x00, 0x00, 0x01, 0x00];

        var parsed = new TdsPacketHeader(header);

        parsed.Length.Should().Be(776);
        parsed.PayloadLength.Should().Be(768);
    }
}
