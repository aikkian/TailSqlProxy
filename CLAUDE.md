# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TDS (Tabular Data Stream) protocol proxy for Azure SQL Database. Sits between SQL clients (SSMS, DataGrip, applications) and Azure SQL to monitor, audit, and control all SQL traffic.

**Target:** .NET 10.0 | **Tests:** 431+ (xUnit + FluentAssertions) | **Solution:** `TailSqlProxy.sln`

## Build and Test Commands

```bash
dotnet build                                    # Build solution
dotnet test                                     # Run all tests
dotnet test --filter "ClassName=SqlInjection"    # Run tests by class name
dotnet test --filter "FullyQualifiedName~Unbounded" # Run tests matching pattern

# Run proxy (MUST run from project dir for appsettings.json to load)
cd src/TailSqlProxy && dotnet run

# Run with debug logging
cd src/TailSqlProxy && Serilog__MinimumLevel__Default=Debug dotnet run

# Run with Development environment (skips appsettings.Production.json)
cd src/TailSqlProxy && DOTNET_ENVIRONMENT=Development dotnet run

# Publish for Linux ARM64 deployment
dotnet publish src/TailSqlProxy -c Release -r linux-arm64 --self-contained true -o ./publish
```

**Critical:** Running `dotnet run --project src/TailSqlProxy` from the repo root does NOT load `appsettings.json` — the content root defaults to the working directory, not the project directory. Always `cd` into `src/TailSqlProxy` first, or set `DOTNET_ENVIRONMENT` with env var overrides.

## Architecture

```
Client (SSMS/DataGrip) → [TLS] → TailSqlProxy ──┬──→ [TLS] → Azure SQL Primary (read-write)
                                   ↓              └──→ [TLS] → Azure SQL Replica (read-only)
                          Rule Engine (inspect & block)
                                   ↓
                          Read/Write Router (classify & route)
                                   ↓
                          Audit Logger (Serilog + Datadog + Prometheus)
```

### Connection Flow

1. **TCP Accept** → peek first byte to detect TDS version (0x16 = TDS 8.0, 0x12 = TDS 7.x)
2. **PreLogin exchange** — TDS 7.x: raw TCP; TDS 8.0: proxy generates PreLogin for server
3. **TLS** — TDS 7.x: wrapped in TDS PreLogin packets via `TdsPreLoginWrapperStream` (TLS 1.2 only to avoid post-handshake ticket corruption); TDS 8.0: raw TLS
4. **Login7** — extract user/db/app, rewrite ServerName to target host (clients send "localhost"), handle FedAuth/Entra ID
5. **Azure SQL Redirect** — if gateway sends ENVCHANGE Routing token, follow redirect to database node transparently
6. **Bidirectional Relay** — two concurrent tasks (client→server + server→client) with MARS support

### Key Design Decisions

- **Login7 ServerName rewriting:** Clients connecting to the proxy send "localhost" or the proxy's DNS name. The proxy rewrites the Login7 packet's ServerName field to the target Azure SQL hostname, adjusting all pointer offsets including the nested FeatureExt pointer.
- **Azure SQL Redirect handling:** Azure SQL's Redirect connection policy (default for in-Azure clients) sends clients directly to the database node after login. The proxy intercepts this, follows the redirect itself, and keeps the client connected through the proxy. External clients (outside Azure) use Proxy mode and don't encounter redirects.
- **FedAuth/Entra ID:** Login response forwarding detects DONE_MORE to distinguish FedAuth challenges from completed logins. The proxy relays FedAuth tokens between client and server.
- **TDS 7.x TLS passthrough:** `TdsPreLoginWrapperStream` wraps/unwraps TLS bytes in TDS PreLogin packets during handshake, then switches to passthrough mode for post-handshake data.
- **Read/Write Split:** `QueryClassifier` uses TSql170Parser AST to detect read-only queries. Read-only replica connection is lazy (established on first SELECT). `TransactionTracker` forces primary routing during active transactions.

## Configuration

All configuration is in `appsettings.json`. Per-instance overrides via environment variables (e.g., `TargetServer__Host=...`).

Key sections:
- **`Proxy`** — ListenPort (1433), ListenAddress, MaxConcurrentConnections (100), AllowedClientIps, Certificate (AutoGenerate), AuditLogPath
- **`TargetServer`** — Host (Azure SQL FQDN), Port
- **`ReadWriteSplit`** — Enabled, ReadOnlyHost, AlwaysPrimaryAppNames[], AlwaysReadOnlyAppNames[]
- **`Rules`** — BypassUsers[], BypassAppNames[], BypassClientIps[]
  - `SqlInjection` — AST + 29 regex patterns (100ms timeout to prevent ReDoS)
  - `UnboundedSelect` / `UnboundedDelete` — Mode=Block or Mode=Timeout
  - `AccessControl` — Policy-based table/column/operation rules
  - `SsmsMetadata` — BlockedAppNames[] (empty = block all apps), BlockedSystemViews[], BlockedProcedures[]
  - `QueryTimeout` — Global fallback timeout
- **`Metrics`** — Enabled, Port (9090), SlowQueryThresholdMs, DurationBuckets[]

**Production:** `appsettings.Production.json` overrides log paths to `/var/log/tailsqlproxy/`. Multi-instance deployments use env files at `/etc/tailsqlproxy/<instance>.env`.

## DI Registration Order (Program.cs)

```
Config     → ProxyOptions, TargetServerOptions, RuleOptions, MetricsOptions, ReadWriteSplitOptions
Singleton  → CertificateProvider, TlsBridge, TdsProxyServer
Scoped     → ClientSession (per-connection)
Singleton  → SqlInjectionRule, AccessControlRule, UnboundedSelectRule, UnboundedDeleteRule, SsmsMetadataRule (IQueryRule)
Singleton  → RuleEngine (IRuleEngine)
Singleton  → AuditLogger (IAuditLogger) — auto-creates log directories
Singleton  → ProxyMetrics (IProxyMetrics) — or NullProxyMetrics if disabled
Hosted     → MetricsHostedService, ProxyHostedService
```

## Protocol Details

- **TDS versions:** 8.0 (direct TLS) and 7.x (PreLogin-first). Version detected by peeking first byte via `SocketFlags.Peek`.
- **TLS 1.2 only for wrapped paths** — TLS 1.3 emits post-handshake NewSessionTicket messages that corrupt the `TdsPreLoginWrapperStream` on Linux OpenSSL.
- **Packet format:** 8-byte big-endian header (Type, Status, Length, SPID, PacketID, Window)
- **DONE token detection:** 0xFD/0xFE, 13 bytes total, checks DONE_MORE bit (0x0001) for response boundary
- **Login7 pointer offsets:** String pointers at bytes 36-86 (each 2-byte offset + 2-byte length). FeatureExt has a nested pointer: ibExtension at offset 56 → 4-byte offset to FeatureExt data.
- **Blocked responses:** TDS ERROR token (0xAA, severity 16) so clients display proper SQL error messages
- **SQL extraction:** SqlBatch: skip ALL_HEADERS (4-byte LE length) → UTF-16LE text. RPC: proc name + sp_executesql parameter.

## Concurrency

- **Bidirectional relay:** Two concurrent tasks with `Task.WhenAny` for disconnect detection
- **Write locks:** `SemaphoreSlim` on client, server, and read-only streams
- **Connection limit:** Atomic `Interlocked.Increment` with rollback on over-limit
- **Server→client relay:** 500ms read timeout polling loop for query timeout CTS checking
- **Thread pool:** `SetMinThreads(200, 200)` for Linux deployment

## Deployment

- **AWS (recommended):** EC2 ARM64 instance, multiple private IPs + Elastic IPs. Source-based routing not needed — AWS routes outbound through each IP's EIP automatically. See `deployment-aws.md`.
- **Azure VM:** Same approach but requires Azure SQL connection policy set to "Proxy" (not "Redirect") to prevent the gateway from redirecting clients away from the proxy.
- **systemd:** Template unit `tailsqlproxy@.service` with `EnvironmentFile=/etc/tailsqlproxy/%i.env`. Use `Type=exec` (not `Type=notify` — .NET doesn't call `sd_notify` without `UseSystemd()`).
- **Permissions:** `setcap cap_net_bind_service=+ep` for port 1433 binding without root.
- **Dependencies:** `libicu` required on Amazon Linux 2023 (`dnf install libicu`).

## Gotchas

- `appsettings.json` must be in the working directory — `dotnet run --project` from repo root won't find it
- `BlockedAppNames: []` (empty) blocks metadata queries from ALL apps, not just SSMS
- `BypassUsers` bypasses ALL rules including SQL injection — keep the list minimal
- `@@version` is blocked by SqlInjection rule as "information probing" — may break client initialization
- Prometheus `DurationBuckets` must be strictly ascending — .NET config binding can produce duplicates; `ProxyMetrics` applies `Distinct().OrderBy()` defensively
- Self-signed cert regenerates on each restart — users see "certificate changed" warnings unless a real cert is loaded via `Proxy.Certificate.Path`
- `entra-id-user` is a fallback username for FedAuth logins when real UPN extraction isn't available
