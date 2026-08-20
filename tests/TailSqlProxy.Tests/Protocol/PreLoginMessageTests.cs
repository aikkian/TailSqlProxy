using FluentAssertions;
using TailSqlProxy.Protocol.Messages;
using Xunit;

namespace TailSqlProxy.Tests.Protocol;

public class PreLoginMessageTests
{
    // Three options (VERSION, ENCRYPTION, MARS) + terminator. Each option entry is
    // type(1) + offset(2, big-endian) + length(2, big-endian); data area starts at byte 16.
    private static byte[] BuildPayload(byte encryption, byte mars)
    {
        byte[] options =
        [
            0x00, 0x00, 0x10, 0x00, 0x06, // VERSION at offset 16, length 6
            0x01, 0x00, 0x16, 0x00, 0x01, // ENCRYPTION at offset 22, length 1
            0x04, 0x00, 0x17, 0x00, 0x01, // MARS at offset 23, length 1
            0xFF,                           // TERMINATOR
        ];
        byte[] data = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, encryption, mars];

        var payload = new byte[options.Length + data.Length];
        Array.Copy(options, payload, options.Length);
        Array.Copy(data, 0, payload, options.Length, data.Length);
        return payload;
    }

    [Fact]
    public void GetMarsOption_ReturnsNegotiatedValue()
    {
        var message = new PreLoginMessage(BuildPayload(encryption: 0x02, mars: 0x01));

        message.GetMarsOption().Should().Be(0x01);
    }

    [Fact]
    public void SetMarsOff_ZeroesMarsByte_LeavesOtherOptionsUntouched()
    {
        var message = new PreLoginMessage(BuildPayload(encryption: 0x02, mars: 0x01));

        var rewritten = message.SetMarsOff();

        new PreLoginMessage(rewritten).GetMarsOption().Should().Be(0x00);
        new PreLoginMessage(rewritten).GetEncryptionOption().Should().Be(PreLoginMessage.EncryptionOption.NotSupported);
        rewritten.Length.Should().Be(BuildPayload(0x02, 0x01).Length); // length-preserving edit
    }

    [Fact]
    public void SetMarsOff_AlreadyOff_PayloadUnchanged()
    {
        var original = BuildPayload(encryption: 0x00, mars: 0x00);
        var message = new PreLoginMessage(original);

        var rewritten = message.SetMarsOff();

        rewritten.Should().Equal(original);
    }

    [Fact]
    public void SetMarsOff_NoMarsToken_PayloadUnchanged()
    {
        // Only VERSION + ENCRYPTION, no MARS token present.
        byte[] options =
        [
            0x00, 0x00, 0x0B, 0x00, 0x06,
            0x01, 0x00, 0x11, 0x00, 0x01,
            0xFF,
        ];
        byte[] data = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        var payload = new byte[options.Length + data.Length];
        Array.Copy(options, payload, options.Length);
        Array.Copy(data, 0, payload, options.Length, data.Length);

        var message = new PreLoginMessage(payload);

        message.GetMarsOption().Should().BeNull();
        message.SetMarsOff().Should().Equal(payload);
    }
}
