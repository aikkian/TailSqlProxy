namespace TailSqlProxy.Protocol;

public enum TdsPacketType : byte
{
    SqlBatch = 0x01,
    PreTds7Login = 0x02,
    Rpc = 0x03,
    TabularResult = 0x04,
    Attention = 0x06,
    BulkLoad = 0x07,
    FederatedAuthToken = 0x08,
    TransactionManagerRequest = 0x0E,
    Login7 = 0x10,
    Sspi = 0x11,
    PreLogin = 0x12,
}
