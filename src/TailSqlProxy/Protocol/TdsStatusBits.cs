namespace TailSqlProxy.Protocol;

[Flags]
public enum TdsStatusBits : byte
{
    Normal = 0x00,
    EndOfMessage = 0x01,
    IgnoreEvent = 0x02,
    ResetConnection = 0x08,
    ResetConnectionSkipTran = 0x10,
}
