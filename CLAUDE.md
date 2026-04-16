# CLAUDE.md — TailSqlProxy Development Guide

## Project Overview

TDS (Tabular Data Stream) protocol proxy for Azure SQL Database. Sits between SQL clients (SSMS, applications) and Azure SQL to monitor, audit, and control all SQL traffic. Inspired by DataSunrise's database security approach.

**Target:** .NET 10.0 | **Tests:** 329 (xUnit + FluentAssertions) | **Solution:** `TailSqlProxy.sln`

## Quick Commands

```bash
dotnet build                  # Build solution
dotnet test                   # Run all 292 tests
dotnet run --project src/TailSqlProxy  # Run proxy
```

## Architecture

```
Client (SSMS/App) → [TLS] → TailSqlProxy → [TLS] → Azure SQL Database
                              ↓
                     Rule Engine (inspect & block)
                              ↓
                     Audit Logger (Serilog + Datadog)
```

**Connection flow:** TCP Accept → TLS MITM → PreLogin → Login7 (extract user/db/app) → Bidirectional Relay (MARS)

## Project Structure

```
src/TailSqlProxy/
├── Program.cs                          # Host builder, DI, Serilog, ThreadPool(200,200)
├── appsettings.json                    # All configuration
├── Configuration/
│   ├── ProxyOptions.cs                 # Proxy, cert, Datadog config
│   ├── RuleOptions.cs                  # Rule toggles, bypass lists, SQL injection options, UnboundedQueryMode enum, QueryTimeoutOptions
│   ├── TargetServerOptions.cs          # Target Azure SQL host/port
│   └── MetricsOptions.cs              # Prometheus metrics, slow query threshold, histogram buckets
├── Hosting/
│   └── ProxyHostedService.cs           # BackgroundService wrapper
├── Logging/
│   ├── IAuditLogger.cs                 # Interface
│   └── AuditLogger.cs                  # Serilog File + JSON (CompactJsonFormatter) + Datadog sinks, session tracking
├── Protocol/
│   ├── TdsPacketType.cs                # Enum: SqlBatch(0x01), Rpc(0x03), Login7(0x10), etc.
│   ├── TdsStatusBits.cs                # Flags: EndOfMessage, ResetConnection
│   ├── TdsPacketHeader.cs              # 8-byte big-endian header parser
│   ├── TdsPacket.cs                    # Header + payload container
│   ├── TdsMessageReader.cs             # Async multi-packet reassembly
│   ├── TdsMessageWriter.cs             # Async chunked writer (4096 byte packets)
│   └── Messages/
│       ├── PreLoginMessage.cs          # Encryption negotiation tokens
│       ├── Login7Message.cs            # User/DB/App extraction, TDS version, FeatureExt, FedAuth
│       ├── SqlBatchMessage.cs          # ALL_HEADERS skip, UTF-16LE SQL extraction
│       ├── RpcRequestMessage.cs        # Proc name + sp_executesql SQL (15 well-known proc IDs)
│       └── TdsResponseBuilder.cs       # ERROR token (0xAA) + DONE token (0xFD) builder
├── Monitoring/
│   ├── IProxyMetrics.cs                # Interface: query/connection/byte metrics
│   ├── ProxyMetrics.cs                 # Prometheus counters, histograms, gauges (9 metric families)
│   ├── NullProxyMetrics.cs             # No-op implementation when metrics disabled
│   └── MetricsHostedService.cs         # HTTP /metrics endpoint for Prometheus scraping
├── Proxy/
│   ├── TdsProxyServer.cs               # TCP listener, atomic connection limit, connection metrics
│   ├── ClientSession.cs                # Bidirectional relay, query duration tracking, DONE token parsing, timeout enforcement via TDS Attention
│   ├── TlsBridge.cs                    # TLS MITM (TDS 8.0 + 7.x), TdsPreLoginWrapperStream
│   └── CertificateProvider.cs          # Lazy<T> thread-safe cert, auto-gen self-signed RSA-2048
└── Rules/
    ├── IQueryRule.cs                   # Interface: Name, IsEnabled, Evaluate(QueryContext)
    ├── IRuleEngine.cs                  # Interface: Evaluate(QueryContext) → RuleResult
    ├── QueryContext.cs                 # SqlText, ProcedureName, IsRpc, ClientIp, HostName, Username, Database, AppName, SessionId
    ├── RuleResult.cs                   # Sealed record: IsBlocked, Reason, TimeoutMs; static Allow/Block()/AllowWithTimeout()
    ├── RuleEngine.cs                   # Bypass check → iterate rules → tightest timeout; BypassUsers/AppNames/ClientIps, global QueryTimeout fallback
    ├── SqlInjectionRule.cs             # Dual-layer: 29 regex patterns + AST visitor (tautology, UNION, stacked, WAITFOR, xp_cmdshell)
    ├── AccessControlRule.cs            # AST: policy-based table/column/operation access control
    ├── UnboundedSelectRule.cs          # AST: SELECT * without WHERE/TOP — Mode=Block or Mode=Timeout
    ├── UnboundedDeleteRule.cs          # AST: DELETE without WHERE/TOP — Mode=Block or Mode=Timeout
    └── SsmsMetadataRule.cs             # Regex + HashSet: 40+ catalog views, 40+ procs, DMVs, SERVERPROPERTY, app-name filtering

tests/TailSqlProxy.Tests/
├── Monitoring/
│   ├── ProxyMetricsTests.cs            # 11 tests — counters, histograms, gauges, null metrics
│   └── SlowQueryDetectionTests.cs      # 17 tests — threshold detection, DONE token parsing, metrics integration
├── Protocol/
│   ├── TdsPacketHeaderTests.cs         # 7 tests — header parsing, big-endian, round-trip
│   ├── TdsMessageReaderTests.cs        # 5 tests — single/multi-packet, empty stream
│   └── SqlBatchMessageTests.cs         # 5 tests — ALL_HEADERS, Unicode, multi-statement
└── Rules/
    ├── SqlInjectionRuleTests.cs        # 83 tests — all attack types + false-positive avoidance
    ├── AccessControlRuleTests.cs       # 25 tests — table/column/user/app/IP/DB/priority policies
    ├── RuleEngineBypassTests.cs        # 12 tests — user/app/IP bypass, case sensitivity
    ├── UnboundedSelectRuleTests.cs     # 7 tests — SELECT * blocked/allowed scenarios
    ├── UnboundedDeleteRuleTests.cs     # 5 tests — DELETE blocked/allowed scenarios
    ├── QueryTimeoutTests.cs            # 37 tests — RuleResult tri-state, timeout modes, RuleEngine propagation, config defaults
    └── SsmsMetadataRuleTests.cs        # 60 tests — procs, views, DMVs, server props, SET, app-name filter
```

## Key NuGet Packages

| Package | Version | Purpose |
|---------|---------|---------|
| Microsoft.Extensions.Hosting | 10.0.5 | DI, Generic Host |
| Microsoft.SqlServer.TransactSql.ScriptDom | 170.191.0 | TSql170Parser for AST-based SQL analysis |
| Serilog.Extensions.Hosting | 10.0.0 | Structured logging |
| Serilog.Sinks.Datadog.Logs | 0.6.0 | Datadog integration |
| Serilog.Sinks.File | 7.0.0 | Daily-rolling audit logs |
| prometheus-net | 8.2.1 | Prometheus metrics (counters, histograms, gauges) |
| FluentAssertions | 8.9.0 | Test assertions |
| xunit | 2.9.3 | Test framework |

## Configuration (appsettings.json)

Key sections:
- **`Proxy`** — ListenPort (1433), ListenAddress, MaxConcurrentConnections (100), Certificate (AutoGenerate), AuditLogPath, Datadog
- **`TargetServer`** — Host (Azure SQL FQDN), Port
- **`Rules`** — BypassUsers[], BypassAppNames[], BypassClientIps[]
  - `SqlInjection` — Enabled, BlockOnParseErrors, CustomPatterns[]
  - `UnboundedSelect` — Enabled, Mode (Block|Timeout), TimeoutMs (default 300000 = 5 min)
  - `UnboundedDelete` — Enabled, Mode (Block|Timeout), TimeoutMs (default 300000 = 5 min)
  - `QueryTimeout` — Enabled, DefaultTimeoutMs (global fallback timeout for all queries)
  - `AccessControl` — Enabled, Policies[] (Name, Priority, Action, Users, AppNames, ClientIps, Database, ObjectPattern, Columns, Operations)
  - `SsmsMetadata` — Enabled, BlockedProcedures[], BlockedSystemViews[], BlockedSchemas[], AllowedPatterns[], BlockedAppNames[], BlockServerProperties, BlockDmvs, BlockSetStatements
- **`Metrics`** — Enabled, Port (9090), SlowQueryThresholdMs (3600000 = 1 hour), DurationBuckets[]

## SQL Firewall Rules

| Rule | Detection | Blocks |
|------|-----------|--------|
| **SqlInjection** | AST + 29 regex patterns | Tautologies (OR 1=1), UNION injection, stacked queries (;DROP), time-based (WAITFOR DELAY), xp_cmdshell, sp_OACreate, OPENROWSET, hex encoding, comment evasion, @@version probing |
| **UnboundedSelect** | AST (TSql170Parser) | SELECT * without WHERE or TOP — Block mode: reject; Timeout mode: allow then kill via TDS Attention after TimeoutMs |
| **UnboundedDelete** | AST (TSql170Parser) | DELETE without WHERE or TOP — Block mode: reject; Timeout mode: allow then kill via TDS Attention after TimeoutMs |
| **AccessControl** | AST (TSql170Parser) | Policy-based table/column/operation access control with user/app/IP/DB scoping, priority ordering |
| **SsmsMetadata** | Regex + HashSet | 40+ catalog views, 40+ metadata procs, DMVs, SERVERPROPERTY, SET statements, app-name filtering |

**Bypass:** Users/apps/IPs in bypass lists skip all rule evaluation. Bypassed queries are still audit-logged.

## Concurrency Design

- **Bidirectional relay:** Two concurrent tasks (client→server + server→client) for MARS support
- **Write locks:** SemaphoreSlim on both client and server streams to prevent interleaved TDS packets
- **Connection limit:** Atomic increment-and-rollback pattern (Interlocked)
- **Certificate:** Lazy<T> with ExecutionAndPublication for thread-safe initialization
- **Thread pool:** SetMinThreads(200, 200) for Linux deployment
- **Response timeout:** 5-minute timeout on login-phase response forwarding

## TDS Protocol Support

- **TDS 8.0:** Full TLS from first byte, FedAuth (Azure AD/Entra ID), FeatureExt negotiation
- **TDS 7.x:** TLS wrapped in PreLogin packets (TdsPreLoginWrapperStream adapter)
- **Packet format:** 8-byte big-endian header (Type, Status, Length, SPID, PacketID, Window)
- **Message types handled:** SqlBatch, RPC, Login7, PreLogin, FederatedAuthToken, Attention, TabularResult
- **SQL extraction:** ALL_HEADERS (4-byte LE length) → UTF-16LE text for SqlBatch; proc name + sp_executesql parameter for RPC

## DI Registration Order (Program.cs)

```
Services:
  Singleton  → CertificateProvider, TlsBridge, TdsProxyServer
  Scoped     → ClientSession (per-connection)
  Singleton  → SqlInjectionRule, AccessControlRule, UnboundedSelectRule, UnboundedDeleteRule, SsmsMetadataRule (IQueryRule)
  Singleton  → RuleEngine (IRuleEngine)
  Singleton  → AuditLogger (IAuditLogger)
  Singleton  → ProxyMetrics (IProxyMetrics) — or NullProxyMetrics if disabled
  Hosted     → MetricsHostedService (Prometheus /metrics HTTP endpoint)
  Hosted     → ProxyHostedService
```

## Planned Features (DataSunrise-Inspired Roadmap)

- **Phase 2:** ~~Granular access control (column/table/operation-level policies), enhanced audit trail (query duration, row counts, session IDs, JSON format)~~ ✓ DONE
- **Phase 3:** Real-time alerting (webhook, email, Syslog), rate limiting (per-user query throttling)
- **Phase 4:** Dynamic data masking (column-based, role-aware, TDS response rewriting)
- **Phase 5:** Sensitive data discovery (auto-scan INFORMATION_SCHEMA, PII/PHI pattern matching), query whitelist/learning mode
- **Phase 6:** ~~Query performance monitoring (slow query detection, Prometheus metrics)~~ ✓ DONE — management REST API (deferred)
- **Phase 7:** ~~Query timeout enforcement (unbounded query timeout mode, TDS Attention signal, global query timeout)~~ ✓ DONE

## Development Notes

- All SQL analysis uses `TSql170Parser` (SQL Server 2025 syntax support)
- Blocked queries return proper TDS ERROR tokens (severity 16) so clients display SQL error messages
- Regex patterns in SqlInjectionRule have 100ms timeout to prevent ReDoS
- `X509CertificateLoader` used instead of obsolete `X509Certificate2` constructor (SYSLIB0057)
- Audit log SQL truncated to 4000 chars max
- DONE token detection: 0xFD/0xFE, 13 bytes, checks DONE_MORE bit (0x0001) for response boundary
- SsmsMetadata rule supports app-name-based blocking (only block from SSMS, allow app queries through)
- AccessControl uses AST visitor to extract table/column references from SELECT/INSERT/UPDATE/DELETE including JOINs
- Audit logger writes dual output: rolling text file + structured JSON (CompactJsonFormatter) with session IDs
- Query duration tracked via DONE token detection in server→client relay; ConcurrentQueue for pending query contexts
- Prometheus metrics: 9 metric families (queries_total, blocked_queries_total, slow_queries_total, query_duration_seconds histogram, active_connections gauge, connections_total, rejected_connections_total, bytes_relayed_total, timeout_killed_total)
- Slow query detector logs SLOW_QUERY entries when duration exceeds configurable threshold (default 1 hour)
- Metrics HTTP endpoint on configurable port (default 9090) using HttpListener; disabled when Metrics.Enabled = false
- RuleResult tri-state: Allow / Block / AllowWithTimeout(ms, reason) — enables runtime query governance
- Query timeout enforcement: CancellationTokenSource.CancelAfter + TDS Attention signal (packet type 0x06) kills long-running queries
- UnboundedSelect/Delete rules support Mode=Block (reject immediately) or Mode=Timeout (allow but kill after TimeoutMs)
- RuleEngine picks tightest (smallest) timeout when multiple rules return AllowWithTimeout; falls back to global QueryTimeout
- Timeout polling: server→client relay uses 500ms read timeout to check for timeout CTS cancellation
