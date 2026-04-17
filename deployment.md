# Deployment Guide

Reference for deploying TailSqlProxy to an Azure VM (Linux ARM64). Covers two topologies:

1. **Single-instance** (sections 1–10) — one proxy on :1433, one upstream Azure SQL. Simplest path, good for dev or a single database.
2. **Multi-instance** (section 11) — one proxy instance per upstream, each bound to a dedicated VM private/public IP on :1433. Clients use natural `<instance>.sql.<your-domain>` hostnames.

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

## 11. Multi-instance on :1433 (one instance per upstream)

Routes multiple Azure SQL upstreams through :1433 by running one proxy instance per upstream, each bound to a dedicated private IP on the VM NIC. Clients pick the upstream by which public IP (hostname) they connect to.

### Topology

```
Client
   ↓ mercury.sql.<your-domain>,1433  →  <pip-1>
Azure VM NIC (5 IP configurations on one NIC)
   ├─ 172.21.0.4  ↔  <pip-1>  →  tailsqlproxy@mercury  →  example-mercury.database.windows.net
   ├─ 172.21.0.5  ↔  <pip-2>  →  tailsqlproxy@venus    →  example-venus.database.windows.net
   ├─ 172.21.0.6  ↔  <pip-3>  →  tailsqlproxy@earth    →  example-earth.database.windows.net
   ├─ 172.21.0.7  ↔  <pip-4>  →  tailsqlproxy@mars     →  example-mars.database.windows.net
   └─ 172.21.0.8  ↔  <pip-5>  →  tailsqlproxy@jupiter  →  example-jupiter.database.windows.net
```

All 5 instances share `/opt/tailsqlproxy/` (one binary). Per-instance overrides come from `/etc/tailsqlproxy/<instance>.env`. Each instance writes to its own `/var/log/tailsqlproxy/<instance>/` and exposes a unique metrics port.

### 11.1 Prerequisites (Azure Portal)

1. **Create N extra Public IP resources** (Standard SKU, Static, same region as VM). Name them e.g. `tailsqlproxy-ip1..4` so they're easy to pick from a dropdown.
2. **Add N secondary IP configurations** to the VM's NIC (VM → Networking → NIC → IP configurations → + Add):
   - Name: `ipconfig<N>` (e.g. `ipconfig2`, `ipconfig3`, …)
   - Type: Secondary
   - Private IP allocation: Dynamic (OK) or Static (if you want a specific value)
   - Associate public IP: pick the matching public IP you created
3. **NSG** — if the :1433 rule is attached at NIC or subnet level, it already covers every IP on the NIC. Nothing to change.

After this you should have N+1 total IP configurations on one NIC, each with a private + public IP.

### 11.2 Guest OS: make the secondary private IPs visible

Azure adds the secondaries to the NIC in the fabric, but Ubuntu's cloud-init netplan only configures the primary via DHCP. Add a **separate** netplan file for the secondaries — don't touch the cloud-init one.

Query IMDS to confirm all IPs are assigned at the NIC level:

```bash
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress?api-version=2023-07-01" \
  | python3 -m json.tool
```

Write `/etc/netplan/60-secondary-ips.yaml` listing the secondary private IPs (match the subnet prefix of your VNet):

```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 172.21.0.5/24
        - 172.21.0.6/24
        - 172.21.0.7/24
        - 172.21.0.8/24
```

```bash
sudo chmod 600 /etc/netplan/60-secondary-ips.yaml
sudo netplan apply
ip -4 addr show eth0 | grep "inet "   # should list all N+1 IPs
```

### 11.3 Stop the single-instance service (if running)

```bash
sudo systemctl stop tailsqlproxy.service
sudo systemctl disable tailsqlproxy.service
```

(The binary in `/opt/tailsqlproxy/` stays — the template unit reuses it.)

### 11.4 Per-instance env files

Create one env file per instance in `/etc/tailsqlproxy/<instance>.env`. .NET reads these as config overrides (`Section__Key` naming maps to `Section:Key` in `appsettings.json`).

Example (`/etc/tailsqlproxy/mercury.env`):

```
Proxy__ListenAddress=172.21.0.4
TargetServer__Host=example-mercury.database.windows.net
Proxy__AuditLogPath=/var/log/tailsqlproxy/mercury/audit-.log
Proxy__AuditJsonLogPath=/var/log/tailsqlproxy/mercury/audit-json-.log
Metrics__Port=9090
```

Repeat for each instance, bumping `ListenAddress` / `TargetServer__Host` / `Metrics__Port`. Per-instance log dirs must exist and be owned by `tdsproxy`:

```bash
for inst in mercury venus earth mars jupiter; do
  sudo install -d -o tdsproxy -g tdsproxy -m 750 /var/log/tailsqlproxy/$inst
done
sudo chmod 640 /etc/tailsqlproxy/*.env
sudo chown root:tdsproxy /etc/tailsqlproxy/*.env
```

### 11.5 systemd template unit

Install `/etc/systemd/system/tailsqlproxy@.service`:

```ini
[Unit]
Description=TailSqlProxy instance %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tdsproxy
Group=tdsproxy
WorkingDirectory=/opt/tailsqlproxy
EnvironmentFile=/etc/tailsqlproxy/%i.env
Environment=DOTNET_ENVIRONMENT=Production
Environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
ExecStart=/opt/tailsqlproxy/TailSqlProxy
Restart=always
RestartSec=5
LimitNOFILE=65536

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

Reload and start all instances:

```bash
sudo systemctl daemon-reload
for inst in mercury venus earth mars jupiter; do
  sudo systemctl enable --now tailsqlproxy@$inst.service
done
```

### 11.6 Verify

```bash
# all 5 active?
for inst in mercury venus earth mars jupiter; do
  printf "%-10s : " "$inst"
  systemctl is-active tailsqlproxy@$inst.service
done

# listeners bound to their private IPs on :1433?
sudo ss -tlnp | grep ':1433'

# metrics ports unique?
sudo ss -tlnp | grep -E ':909[0-9]'

# end-to-end (from a client) — each public IP should reach its own upstream
sqlcmd -S tcp:<pip-1>,1433 -U <user> -P '<pw>' -C -N true -Q "SELECT @@SERVERNAME"
```

Expected: `@@SERVERNAME` returns the upstream of that specific instance (e.g. hitting `<pip-1>` returns `example-mercury`'s name; `<pip-2>` returns `example-venus`'s; etc.).

### 11.7 DNS

Create A records (in whatever DNS you control for `<your-domain>`):

```
mercury.sql.<your-domain>  → <pip-1>
venus.sql.<your-domain>    → <pip-2>
earth.sql.<your-domain>    → <pip-3>
mars.sql.<your-domain>     → <pip-4>
jupiter.sql.<your-domain>  → <pip-5>
```

TTL 300s is fine. Clients then connect via the subdomain rather than raw IP.

### 11.8 Azure SQL firewall

Every upstream Azure SQL Server must allow the VM's outbound public IP in its **Networking → Firewall rules**. If the server uses a strict whitelist and doesn't include the VM's outbound IP, the proxy will relay an Azure SQL firewall error back to the client like:

```
Cannot open server '…' requested by the login. Client with IP address '<IP>' is not allowed to access the server.
```

Fix by either:
- Adding the VM's outbound public IP(s) to each server's firewall rules, or
- Enabling **Allow Azure services and resources to access this server** on each server.

### 11.9 Client connection strings

```
jdbc:sqlserver://mercury.sql.<your-domain>:1433;encrypt=true;trustServerCertificate=true;database=<db>
jdbc:sqlserver://venus.sql.<your-domain>:1433;encrypt=true;trustServerCertificate=true;database=<db>
```

```bash
sqlcmd -S tcp:mercury.sql.<your-domain>,1433 -U <user> -P '<pw>' -C -N true
```

### 11.10 Updating (replace the binary across all instances)

```bash
# build machine
dotnet publish src/TailSqlProxy -c Release -r linux-arm64 --self-contained true -o ./publish
tar -czf /tmp/tailsqlproxy.tar.gz -C publish .
scp -i ~/Downloads/tailsqlproxy_key.pem /tmp/tailsqlproxy.tar.gz tailsqlproxy@<VM_IP>:/tmp/

# VM
for inst in mercury venus earth mars jupiter; do
  sudo systemctl stop tailsqlproxy@$inst.service
done
sudo tar -xzf /tmp/tailsqlproxy.tar.gz -C /opt/tailsqlproxy
sudo chown -R tdsproxy:tdsproxy /opt/tailsqlproxy
sudo setcap 'cap_net_bind_service=+ep' /opt/tailsqlproxy/TailSqlProxy
for inst in mercury venus earth mars jupiter; do
  sudo systemctl start tailsqlproxy@$inst.service
done
```

### 11.11 Adding another instance later

1. Create one more public IP + secondary IP config on the NIC (Azure Portal).
2. Add the new private IP to `/etc/netplan/60-secondary-ips.yaml`, `sudo netplan apply`.
3. Drop an env file at `/etc/tailsqlproxy/<newname>.env`.
4. `sudo mkdir -p /var/log/tailsqlproxy/<newname>` and chown to `tdsproxy`.
5. `sudo systemctl enable --now tailsqlproxy@<newname>.service`.
6. Add a DNS A record.

No template-unit or binary changes required.
