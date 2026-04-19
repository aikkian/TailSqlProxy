# TailSqlProxy

A TDS (Tabular Data Stream) protocol proxy for Azure SQL Database. Sits between SQL clients (SSMS, DataGrip, applications) and Azure SQL to monitor, audit, and control all SQL traffic.

```
Client (SSMS/App) --> [TLS] --> TailSqlProxy --+--> [TLS] --> Azure SQL Primary (read-write)
                                 |             '--> [TLS] --> Azure SQL Replica (read-only)
                            Rule Engine
                           (inspect & block)
                                 |
                          Read/Write Router
                         (classify & route)
                                 |
                            Audit Logger
                         (Serilog + Datadog)
```

## Features

**SQL Firewall** -- AST-based query analysis using TSql170Parser (SQL Server 2025 syntax)
- SQL injection detection (29 regex patterns + AST visitor: tautologies, UNION injection, stacked queries, WAITFOR, xp_cmdshell)
- Unbounded SELECT/DELETE blocking (queries without WHERE or TOP)
- Policy-based access control (table/column/operation-level, scoped by user/app/IP/database)
- SSMS metadata query filtering (catalog views, system procs, DMVs)
- Query timeout enforcement via TDS Attention signal

**Read/Write Split** -- Routes SELECT queries to a read-only replica, DML/transactions to primary
- AST-based query classification (SELECT, SET, DECLARE, PRINT, USE -> replica; everything else -> primary)
- Transaction tracking (BEGIN/COMMIT/ROLLBACK depth)
- App-name overrides (force primary for migration tools, force replica for reporting)

**Audit Logging** -- Every query logged with user, IP, app name, database, session ID, duration
- Daily-rolling text + structured JSON (CompactJsonFormatter)
- Optional Datadog integration
- Blocked queries logged with rule name and reason

**Monitoring** -- Prometheus metrics on configurable HTTP endpoint
- Query counters, duration histograms, slow query detection
- Active connections gauge, bytes relayed, timeout kills
- Connection accept/reject counters

**Protocol Support**
- TDS 8.0 (direct TLS) and TDS 7.x (PreLogin-first with wrapped TLS)
- Entra ID / Azure AD authentication (FedAuth token relay)
- MARS (Multiple Active Result Sets) via bidirectional relay
- Login7 server name rewriting for transparent proxying

## Quick Start

Requires [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
# Build
dotnet build

# Run tests
dotnet test

# Configure target server
# Edit src/TailSqlProxy/appsettings.json:
#   "TargetServer": { "Host": "yourserver.database.windows.net" }

# Run
cd src/TailSqlProxy
dotnet run
```

Connect your SQL client to `localhost:1433` with your Azure SQL credentials. Set `trustServerCertificate=true` (the proxy auto-generates a self-signed certificate).

## Configuration

All configuration is in `appsettings.json`:

| Section | Key settings |
|---------|-------------|
| `Proxy` | ListenPort (1433), ListenAddress, MaxConcurrentConnections (100), AllowedClientIps, Certificate, AuditLogPath |
| `TargetServer` | Host (Azure SQL FQDN), Port |
| `ReadWriteSplit` | Enabled, ReadOnlyHost, AlwaysPrimaryAppNames, AlwaysReadOnlyAppNames |
| `Rules` | BypassUsers/AppNames/ClientIps, SqlInjection, UnboundedSelect/Delete, AccessControl, SsmsMetadata, QueryTimeout |
| `Metrics` | Enabled, Port (9090), SlowQueryThresholdMs, DurationBuckets |

Bypass lists allow specific users/apps/IPs to skip rule evaluation while still being audit-logged.

## Deployment

See [deployment.md](deployment.md) for the full Azure VM (Linux) deployment guide covering:
- Single-instance and multi-instance topologies
- systemd service configuration
- Azure SQL Private Endpoint setup
- Client connection strings

## Tech Stack

- **.NET 10.0** with Microsoft.Extensions.Hosting
- **Microsoft.SqlServer.TransactSql.ScriptDom** (TSql170Parser) for AST-based SQL analysis
- **Serilog** for structured audit logging
- **prometheus-net** for Prometheus metrics
- **xUnit + FluentAssertions** for testing

## License

Proprietary
