using FluentAssertions;
using TailSqlProxy.Protocol;
using TailSqlProxy.Protocol.Messages;
using TailSqlProxy.Proxy;
using Xunit;

namespace TailSqlProxy.Tests.Proxy;

public class ClientSessionPreLoginTests
{
    // VERSION(offset 16, len 6) + ENCRYPTION(offset 22, len 1) + MARS(offset 23, len 1) + terminator,
    // followed by the data area itself.
    private static byte[] BuildPayload(byte mars)
    {
        byte[] options =
        [
            0x00, 0x00, 0x10, 0x00, 0x06,
            0x01, 0x00, 0x16, 0x00, 0x01,
            0x04, 0x00, 0x17, 0x00, 0x01,
            0xFF,
        ];
        byte[] data = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, mars];

        var payload = new byte[options.Length + data.Length];
        Array.Copy(options, payload, options.Length);
        Array.Copy(data, 0, payload, options.Length, data.Length);
        return payload;
    }

    private static TdsPacket MakePacket(byte[] payload, bool eom, byte packetId)
    {
        var header = new TdsPacketHeader(
            TdsPacketType.PreLogin,
            status: eom ? (byte)0x01 : (byte)0x00,
            length: (ushort)(TdsPacketHeader.Size + payload.Length),
            spid: 0,
            packetId: packetId,
            window: 0);

        var raw = new byte[TdsPacketHeader.Size + payload.Length];
        header.WriteTo(raw);
        Array.Copy(payload, 0, raw, TdsPacketHeader.Size, payload.Length);

        return new TdsPacket(header, payload, raw);
    }

    private static byte[] ReassemblePayload(IEnumerable<byte[]> rawPackets) =>
        rawPackets.SelectMany(raw => raw.Skip(TdsPacketHeader.Size)).ToArray();

    [Fact]
    public void RewritePreLoginForcingMarsOff_SinglePacket_ZeroesMarsPreservesRest()
    {
        var payload = BuildPayload(mars: 0x01);
        var packet = MakePacket(payload, eom: true, packetId: 1);
        var message = new TdsMessage(TdsPacketType.PreLogin, payload, [packet]);

        var rawOut = ClientSession.RewritePreLoginForcingMarsOff(message).ToArray();

        rawOut.Should().HaveCount(1);
        rawOut[0].Length.Should().Be(packet.RawBytes.Length); // length-preserving
        rawOut[0].Take(TdsPacketHeader.Size).Should().Equal(packet.RawBytes.Take(TdsPacketHeader.Size)); // header untouched

        var rewrittenMsg = new PreLoginMessage(ReassemblePayload(rawOut));
        rewrittenMsg.GetMarsOption().Should().Be(0x00);
        rewrittenMsg.GetEncryptionOption().Should().Be(PreLoginMessage.EncryptionOption.NotSupported);
    }

    [Fact]
    public void RewritePreLoginForcingMarsOff_MarsByteInSecondPacket_StillRewritten()
    {
        var payload = BuildPayload(mars: 0x01);
        // Split so the MARS data byte (payload offset 23) lands in the second packet.
        var firstPayload = payload[..16];
        var secondPayload = payload[16..];

        var first = MakePacket(firstPayload, eom: false, packetId: 1);
        var second = MakePacket(secondPayload, eom: true, packetId: 2);
        var message = new TdsMessage(TdsPacketType.PreLogin, payload, [first, second]);

        var rawOut = ClientSession.RewritePreLoginForcingMarsOff(message).ToArray();

        rawOut.Should().HaveCount(2);
        rawOut[0].Should().Equal(first.RawBytes); // untouched packet passed through as-is
        rawOut[1].Length.Should().Be(second.RawBytes.Length);
        rawOut[1].Take(TdsPacketHeader.Size).Should().Equal(second.RawBytes.Take(TdsPacketHeader.Size));

        var rewrittenMsg = new PreLoginMessage(ReassemblePayload(rawOut));
        rewrittenMsg.GetMarsOption().Should().Be(0x00);
    }

    [Fact]
    public void RewritePreLoginForcingMarsOff_MarsAlreadyOff_PacketsUnchanged()
    {
        var payload = BuildPayload(mars: 0x00);
        var packet = MakePacket(payload, eom: true, packetId: 1);
        var message = new TdsMessage(TdsPacketType.PreLogin, payload, [packet]);

        var rawOut = ClientSession.RewritePreLoginForcingMarsOff(message).ToArray();

        rawOut.Should().HaveCount(1);
        rawOut[0].Should().Equal(packet.RawBytes);
    }
}
