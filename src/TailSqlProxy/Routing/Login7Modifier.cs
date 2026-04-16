using System.Buffers.Binary;

namespace TailSqlProxy.Routing;

/// <summary>
/// Modifies Login7 packet payloads to set ApplicationIntent=ReadOnly.
/// In the TDS Login7 packet, TypeFlags is at offset 32 (1 byte).
/// Bit 5 (0x20) of TypeFlags = fReadOnlyIntent.
/// Setting this bit tells Azure SQL to route to a read-only replica.
/// </summary>
public static class Login7Modifier
{
    // TypeFlags byte is at offset 32 in the Login7 payload (MS-TDS 2.2.6.4)
    private const int TypeFlagsOffset = 32;
    private const byte ReadOnlyIntentBit = 0x20; // bit 5

    /// <summary>
    /// Returns a copy of the Login7 payload with ApplicationIntent=ReadOnly set.
    /// </summary>
    public static byte[] SetReadOnlyIntent(byte[] payload)
    {
        if (payload.Length <= TypeFlagsOffset)
            return payload;

        var modified = new byte[payload.Length];
        Array.Copy(payload, modified, payload.Length);

        modified[TypeFlagsOffset] |= ReadOnlyIntentBit;

        return modified;
    }

    /// <summary>
    /// Returns true if the Login7 payload has ApplicationIntent=ReadOnly set.
    /// </summary>
    public static bool HasReadOnlyIntent(byte[] payload)
    {
        if (payload.Length <= TypeFlagsOffset)
            return false;

        return (payload[TypeFlagsOffset] & ReadOnlyIntentBit) != 0;
    }
}
