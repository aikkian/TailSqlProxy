using System.Buffers.Binary;
using System.Text;

namespace TailSqlProxy.Protocol.Messages;

public class Login7Message
{
    // Login7 fixed-header offsets (MS-TDS 2.2.6.4)
    // Each pointer is 4 bytes: 2 bytes offset (from start of Login7 data) + 2 bytes length (in chars)
    private const int HostNamePtrOffset = 36;
    private const int UserNamePtrOffset = 40;
    private const int PasswordPtrOffset = 44;
    private const int AppNamePtrOffset = 48;
    private const int ServerNamePtrOffset = 52;
    private const int CltIntNamePtrOffset = 60;
    private const int DatabasePtrOffset = 68;
    // TDS 7.4+ (TDS 8.0) FeatureExt pointer at offset 84
    private const int FeatureExtPtrOffset = 84;

    // OptionFlags3 at offset 34 contains the fExtension bit (0x10)
    private const int OptionFlags3Offset = 34;

    // TDS 7.4+ FeatureExt feature IDs (MS-TDS 2.2.6.4)
    public enum FeatureId : byte
    {
        SessionRecovery = 0x01,
        FedAuth = 0x02,
        ColumnEncryption = 0x04,
        GlobalTransactions = 0x05,
        AzureSqlSupport = 0x08,
        DataClassification = 0x09,
        Utf8Support = 0x0A,
        AzureSqlDnsCaching = 0x0B,
        Terminator = 0xFF,
    }

    // FedAuth library type (MS-TDS 2.2.6.4)
    public enum FedAuthLibrary : byte
    {
        SecurityToken = 0x01,      // Token from STS (e.g. AAD/Entra ID ADAL/MSAL)
        ADAL = 0x02,               // Deprecated - ADAL workflow
        MsalInteractive = 0x03,    // MSAL interactive
        MsalManagedIdentity = 0x04,// MSAL managed identity
    }

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

    /// <summary>
    /// Returns true if the Login7 includes a FeatureExt block (TDS 7.4+ / TDS 8.0).
    /// </summary>
    public bool HasFeatureExtension()
    {
        if (_payload.Length <= OptionFlags3Offset)
            return false;
        return (_payload[OptionFlags3Offset] & 0x10) != 0;
    }

    /// <summary>
    /// Parses the TDS 7.4+ FeatureExt block and returns the negotiated feature IDs.
    /// </summary>
    public IReadOnlyList<FeatureId> GetRequestedFeatures()
    {
        var features = new List<FeatureId>();
        try
        {
            if (!HasFeatureExtension())
                return features;

            var span = _payload.AsSpan();

            // The FeatureExt offset pointer is at a fixed location in the Login7
            // For TDS 7.4+, the extension offset is stored at the Extension pointer location.
            // However, the actual FeatureExt data is at the offset pointed to by
            // the ibExtension field (offset 84, length field at 86 is unused for extension).
            if (FeatureExtPtrOffset + 4 > span.Length)
                return features;

            uint extOffset = BinaryPrimitives.ReadUInt32LittleEndian(span[FeatureExtPtrOffset..]);
            if (extOffset == 0 || extOffset >= (uint)span.Length)
                return features;

            int offset = (int)extOffset;

            // FeatureExt is a list of: FeatureId(1 byte) + FeatureDataLen(4 bytes) + FeatureData(variable)
            // Terminated by FeatureId = 0xFF
            while (offset < span.Length)
            {
                byte featureId = span[offset];
                offset++;

                if (featureId == (byte)FeatureId.Terminator)
                    break;

                if (offset + 4 > span.Length)
                    break;

                uint dataLen = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..]);
                offset += 4;

                features.Add((FeatureId)featureId);

                offset += (int)dataLen;
            }
        }
        catch
        {
            // Gracefully handle malformed packets
        }

        return features;
    }

    /// <summary>
    /// Returns true if the client requested FedAuth (Azure AD/Entra ID) authentication.
    /// </summary>
    public bool RequestsFedAuth()
    {
        return GetRequestedFeatures().Contains(FeatureId.FedAuth);
    }

    /// <summary>
    /// Extracts the TDS version from bytes 4-7 of the Login7 payload.
    /// Format: major.minor.build (e.g., 0x74000004 = TDS 7.4 rev 4 = "TDS 8.0")
    /// </summary>
    public (byte Major, byte Minor, ushort Build) ExtractTdsVersion()
    {
        if (_payload.Length < 8)
            return (0, 0, 0);

        // TDS version is at offset 4 in Login7 (bytes 4-7), stored as:
        // byte[4] = TdsVersion[3] (major), byte[5] = TdsVersion[2] (minor)
        // byte[6..7] = TdsVersion[0..1] (build, little-endian)
        return (_payload[4], _payload[5], BinaryPrimitives.ReadUInt16LittleEndian(_payload.AsSpan(6)));
    }

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
