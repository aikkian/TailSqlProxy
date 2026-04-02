using System.Buffers.Binary;
using System.Text;

namespace TailSqlProxy.Protocol.Messages;

public class Login7Message
{
    // Login7 fixed-header offsets for variable-length data pointers
    // Each pointer is 4 bytes: 2 bytes offset (from start of Login7 data) + 2 bytes length (in chars)
    private const int HostNamePtrOffset = 36;
    private const int UserNamePtrOffset = 40;
    private const int PasswordPtrOffset = 44;
    private const int AppNamePtrOffset = 48;
    private const int ServerNamePtrOffset = 52;
    private const int CltIntNamePtrOffset = 60;
    private const int DatabasePtrOffset = 68;

    private readonly byte[] _payload;

    public Login7Message(TdsMessage message)
    {
        if (message.Type != TdsPacketType.Login7)
            throw new ArgumentException("Message is not a Login7.", nameof(message));
        _payload = message.Payload;
    }

    public Login7Message(byte[] payload)
    {
        _payload = payload;
    }

    public string? ExtractUsername() => ExtractString(UserNamePtrOffset);
    public string? ExtractDatabase() => ExtractString(DatabasePtrOffset);
    public string? ExtractAppName() => ExtractString(AppNamePtrOffset);
    public string? ExtractHostName() => ExtractString(HostNamePtrOffset);
    public string? ExtractServerName() => ExtractString(ServerNamePtrOffset);
    public string? ExtractClientInterfaceName() => ExtractString(CltIntNamePtrOffset);

    private string? ExtractString(int pointerOffset)
    {
        try
        {
            var span = _payload.AsSpan();
            if (pointerOffset + 4 > span.Length)
                return null;

            ushort dataOffset = BinaryPrimitives.ReadUInt16LittleEndian(span[pointerOffset..]);
            ushort charLength = BinaryPrimitives.ReadUInt16LittleEndian(span[(pointerOffset + 2)..]);

            if (charLength == 0)
                return string.Empty;

            int byteLength = charLength * 2;
            if (dataOffset + byteLength > span.Length)
                return null;

            return Encoding.Unicode.GetString(span.Slice(dataOffset, byteLength));
        }
        catch
        {
            return null;
        }
    }
}
