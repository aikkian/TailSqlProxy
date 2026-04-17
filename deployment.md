# Deployment Guide

Reference for deploying TailSqlProxy to an Azure VM (Linux ARM64), single-instance on :1433.

## Architecture

```
Client (SSMS / DataGrip / sqlcmd)
        ↓ TCP/1433 (TDS + TLS)
Azure VM (Ubuntu 24.04 ARM64)
        ↓
TailSqlProxy (systemd service, runs as `tdsproxy` user)
        ↓ TCP/1433 (TDS 7.x + TLS 1.2)
Azure SQL Database (example-*.database.windows.net)
```

## Target environment

| | |
|---|---|
| VM size | E2pds v6 (2 vCPU, ~16 GB RAM, ARM64) |
| OS | Ubuntu 24.04 LTS (`aarch64`) |
| Runtime | self-contained .NET 10 (bundled in publish output) |
| Service user | `tdsproxy` (system user, no login) |
| Install dir | `/opt/tailsqlproxy/` |
| Log dir | `/var/log/tailsqlproxy/` |
| Systemd unit | `tailsqlproxy.service` |

## Prerequisites

- Azure VM provisioned with Ubuntu 24.04 LTS ARM64
- Public IP attached, NSG allows inbound :1433 from client CIDRs
- SSH key access (example: `~/Downloads/tailsqlproxy_key.pem`)
- `.NET 10 SDK` on the build machine (macOS, Linux, or Windows)

## 1. Build the ARM64 self-contained binary

On the build machine:

```bash
cd <repo-root>
dotnet publish src/TailSqlProxy -c Release -r linux-arm64 \
  --self-contained true -o ./publish
tar -czf /tmp/tailsqlproxy.tar.gz -C publish .
```

Output is ~90 MB. Self-contained means no runtime install needed on the VM.

## 2. Upload to the VM

```bash
scp -i ~/Downloads/tailsqlproxy_key.pem \
  /tmp/tailsqlproxy.tar.gz \
  tailsqlproxy@<VM_IP>:/tmp/
```

## 3. First-time VM setup

Run once on the VM:

```bash
ssh -i ~/Downloads/tailsqlproxy_key.pem tailsqlproxy@<VM_IP> 'sudo bash -s' <<'PROVISION'
set -euo pipefail

# service user
if ! id -u tdsproxy >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin tdsproxy
fi

# directories
install -d -o tdsproxy -g tdsproxy -m 750 /opt/tailsqlproxy
install -d -o tdsproxy -g tdsproxy -m 750 /var/log/tailsqlproxy

# extract binaries
tar -xzf /tmp/tailsqlproxy.tar.gz -C /opt/tailsqlproxy
chown -R tdsproxy:tdsproxy /opt/tailsqlproxy
chmod +x /opt/tailsqlproxy/TailSqlProxy

# allow non-root to bind :1433
setcap 'cap_net_bind_service=+ep' /opt/tailsqlproxy/TailSqlProxy
PROVISION
```

## 4. Production configuration

Write `/opt/tailsqlproxy/appsettings.Production.json` on the VM:

```json
{
  "Proxy": {
    "AuditLogPath": "/var/log/tailsqlproxy/audit-.log",
    "AuditJsonLogPath": "/var/log/tailsqlproxy/audit-json-.log",
    "AllowedClientIps": []
  },
  "TargetServer": {
    "Host": "example-mercury.database.windows.net",
    "Port": 1433
  },
  "ReadWriteSplit": {
    "Enabled": true
  }
}
```

Lock down:

```bash
sudo chown tdsproxy:tdsproxy /opt/tailsqlproxy/appsettings.Production.json
sudo chmod 640 /opt/tailsqlproxy/appsettings.Production.json
```

Notes:
- `AllowedClientIps` — leave `[]` to allow all, or list client IPs for a whitelist.
- `TargetServer.Host` is required. Service will fail to forward connections if empty.
- Datadog and other overrides go in the same file. Keep `appsettings.json` (in install dir) untouched — it's the defaults.

## 5. systemd unit

Install `/etc/systemd/system/tailsqlproxy.service`:

```ini
[Unit]
Description=TailSqlProxy - TDS proxy for Azure SQL
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tdsproxy
Group=tdsproxy
WorkingDirectory=/opt/tailsqlproxy
ExecStart=/opt/tailsqlproxy/TailSqlProxy
Environment=DOTNET_ENVIRONMENT=Production
Environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
Restart=always
RestartSec=5
LimitNOFILE=65536

# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/log/tailsqlproxy /opt/tailsqlproxy
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tailsqlproxy
```

## 6. Verify

```bash
# service up?
sudo systemctl status tailsqlproxy

# live logs
sudo journalctl -u tailsqlproxy -f

# listening?
sudo ss -tlnp | grep -E ":(1433|9090)"

# TCP keepalive armed on sockets?
sudo ss -ntoi | grep -A1 :1433

# end-to-end
sqlcmd -S tcp:<VM_IP>,1433 -U <sqluser> -P '<pw>' -C -Q "SELECT @@VERSION"
```

Expected on startup:

```
TailSqlProxy TDS proxy listening on 0.0.0.0:1433
Prometheus metrics endpoint listening on http://0.0.0.0:9090/metrics/
```

## 7. Azure housekeeping

- **Public IP idle timeout**: raise to 30 min to survive long-running queries (keepalives already handle it, but belt-and-suspenders):
  ```bash
  az network public-ip update -g <rg> -n <pip-name> --idle-timeout 30
  ```
- **NSG**: restrict inbound :1433 to your app/client CIDRs. Keep :9090 (metrics) closed to the internet — open it only to your monitoring CIDR or bind locally.
- **Azure SQL firewall**: must allow the VM's outbound public IP. Otherwise the proxy connects out but Azure SQL rejects.

## 8. Updating

On build machine:

```bash
dotnet publish src/TailSqlProxy -c Release -r linux-arm64 --self-contained true -o ./publish
tar -czf /tmp/tailsqlproxy.tar.gz -C publish .
scp -i ~/Downloads/tailsqlproxy_key.pem /tmp/tailsqlproxy.tar.gz tailsqlproxy@<VM_IP>:/tmp/
```

On VM:

```bash
sudo systemctl stop tailsqlproxy
sudo tar -xzf /tmp/tailsqlproxy.tar.gz -C /opt/tailsqlproxy
sudo chown -R tdsproxy:tdsproxy /opt/tailsqlproxy
sudo setcap 'cap_net_bind_service=+ep' /opt/tailsqlproxy/TailSqlProxy
sudo systemctl start tailsqlproxy
```

## 9. Client configuration

Any SQL client that speaks TDS 7.x or 8.0 works. The proxy presents a self-signed certificate by default, so clients must either trust it or skip validation.

**DataGrip / JDBC**:

```
jdbc:sqlserver://<VM_IP>:1433;encrypt=true;trustServerCertificate=true;database=<db>
```

**sqlcmd (go-sqlcmd)**:

```bash
sqlcmd -S tcp:<VM_IP>,1433 -U <user> -P '<pw>' -C -N true
```

`-C` = `trustServerCertificate`, `-N true` = encrypt.

## 10. Troubleshooting

### Service won't start
`sudo journalctl -u tailsqlproxy -n 100 --no-pager` — look for config errors or missing `TargetServer.Host`.

### Port :1433 not reachable externally
- NSG inbound rule present?
- VM public IP correct?
- Azure outbound from your client network blocks :1433?
- `sudo ss -tlnp | grep 1433` on the VM confirms the proxy is listening.

### TLS handshake failures
- Client must set `trustServerCertificate=true` / `-C`. The auto-generated cert isn't trusted by default.
- Check logs for `Session error`. `Received an unexpected EOF` during TLS usually = client rejected cert.

### Long-running queries drop after ~4 min
- Azure Load Balancer idle timeout. The proxy enables TCP keepalives (60s/30s) on all sockets, so this shouldn't happen. If it does, verify `sudo ss -ntoi | grep :1433` shows `keepalive` timers.
- If using an LB in front of the VM, set `idleTimeoutInMinutes=30` on it.

### Azure SQL auth fails but proxy is fine
- Azure SQL firewall probably blocks the VM's outbound IP. Add the VM's public IP to Azure SQL → Networking → Firewall rules.

## 11. Forward plan — multi-instance on :1433

To route multiple Azure SQL upstreams through a single :1433 (one per subdomain), we'll attach additional secondary public IPs to the VM NIC and run one proxy instance per private IP via a systemd template unit (`tailsqlproxy@<instance>.service`). Each instance:

- binds `ListenAddress` to its private IP on :1433
- targets its own Azure SQL host via `TargetServer__Host` env var
- writes audit logs to `/var/log/tailsqlproxy/<instance>/`
- exposes metrics on a unique port

The shared binary at `/opt/tailsqlproxy/` doesn't change. Per-instance overrides come from `/etc/tailsqlproxy/<instance>.env`.

Client-side DNS maps each subdomain to its dedicated public IP, so clients connect using natural hostnames (e.g. `mercury.sql.example.com,1433`) and each lands on the right proxy instance with the right upstream.

This section will be fleshed out once the additional public IPs are attached.
