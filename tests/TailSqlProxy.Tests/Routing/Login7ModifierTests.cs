using FluentAssertions;
using TailSqlProxy.Routing;
using Xunit;

namespace TailSqlProxy.Tests.Routing;

public class Login7ModifierTests
{
    [Fact]
    public void SetReadOnlyIntent_SetsTypeFlagsBit()
    {
        // Create a minimal Login7 payload (at least 27 bytes to reach TypeFlags at offset 26)
        var payload = new byte[90];
        payload[26] = 0x00; // TypeFlags — no flags set

        var modified = Login7Modifier.SetReadOnlyIntent(payload);

        Login7Modifier.HasReadOnlyIntent(modified).Should().BeTrue();
        (modified[26] & 0x20).Should().NotBe(0, "bit 5 (ReadOnly intent) should be set");
    }

    [Fact]
    public void SetReadOnlyIntent_PreservesExistingFlags()
    {
        var payload = new byte[90];
        payload[26] = 0x05; // Some other flags set (bits 0 and 2)

        var modified = Login7Modifier.SetReadOnlyIntent(payload);

        modified[26].Should().Be(0x25, "should preserve existing flags and add ReadOnly bit");
    }

    [Fact]
    public void SetReadOnlyIntent_IdempotentWhenAlreadySet()
    {
        var payload = new byte[90];
        payload[26] = 0x20; // Already has ReadOnly intent

        var modified = Login7Modifier.SetReadOnlyIntent(payload);

        modified[26].Should().Be(0x20);
        Login7Modifier.HasReadOnlyIntent(modified).Should().BeTrue();
    }

    [Fact]
    public void SetReadOnlyIntent_DoesNotModifyOriginal()
    {
        var payload = new byte[90];
        payload[26] = 0x00;

        var modified = Login7Modifier.SetReadOnlyIntent(payload);

        payload[26].Should().Be(0x00, "original should be unchanged");
        modified[26].Should().Be(0x20);
    }

    [Fact]
    public void HasReadOnlyIntent_ReturnsFalse_WhenNotSet()
    {
        var payload = new byte[90];
        payload[26] = 0x00;

        Login7Modifier.HasReadOnlyIntent(payload).Should().BeFalse();
    }

    [Fact]
    public void HasReadOnlyIntent_ReturnsFalse_WhenPayloadTooShort()
    {
        var payload = new byte[10]; // Too short to have TypeFlags
        Login7Modifier.HasReadOnlyIntent(payload).Should().BeFalse();
    }

    [Fact]
    public void SetReadOnlyIntent_ShortPayload_ReturnsUnmodified()
    {
        var payload = new byte[10];
        var result = Login7Modifier.SetReadOnlyIntent(payload);
        result.Should().Equal(payload);
    }
}
