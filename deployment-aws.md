# TailSqlProxy — AWS Deployment Guide

Deploy 5 proxy instances on a single EC2 instance, each with its own Elastic IP, pointing to different Azure SQL Database endpoints.

## Architecture

```
DNS                    Elastic IP          Private IP       Target Azure SQL
─────────────────────  ──────────────────  ──────────────   ──────────────────────────────────
db.db01.example.com  → EIP-1 (x.x.x.1)  → 10.0.1.10    → example-db01.database.windows.net
db.db02.example.com    → EIP-2 (x.x.x.2)  → 10.0.1.11    → example-db02.database.windows.net
db.db03.example.com    → EIP-3 (x.x.x.3)  → 10.0.1.12    → example-db03.database.windows.net
db.db04.example.com   → EIP-4 (x.x.x.4)  → 10.0.1.13    → example-db04.database.windows.net
db.db05.example.com   → EIP-5 (x.x.x.5)  → 10.0.1.14    → example-db05.database.windows.net
```

All 5 instances listen on port 1433, each bound to its own private IP.

---

## Step 1: Create VPC and Subnet

1. **AWS Console → VPC → Create VPC**
   - Name: `tailsqlproxy-vpc`
   - IPv4 CIDR: `10.0.0.0/16`

2. **Create Subnet**
   - Name: `tailsqlproxy-subnet`
   - VPC: `tailsqlproxy-vpc`
   - Availability Zone: pick one (e.g., `ap-southeast-1a` for Singapore, closest to Azure SE Asia)
   - IPv4 CIDR: `10.0.1.0/24`

3. **Create Internet Gateway**
   - Name: `tailsqlproxy-igw`
   - Attach to `tailsqlproxy-vpc`

4. **Route Table**
   - Select the route table for `tailsqlproxy-vpc`
   - Add route: Destination `0.0.0.0/0` → Target: `tailsqlproxy-igw`
   - Associate with `tailsqlproxy-subnet`

---

## Step 2: Create Security Group

1. **AWS Console → VPC → Security Groups → Create**
   - Name: `tailsqlproxy-sg`
   - VPC: `tailsqlproxy-vpc`

2. **Inbound Rules:**

   | Type | Port | Source | Description |
   |------|------|--------|-------------|
   | Custom TCP | 1433 | 0.0.0.0/0 | SQL proxy (TDS) |
   | SSH | 22 | Your IP/CIDR | Admin access |
   | Custom TCP | 9090-9094 | Your IP/CIDR | Prometheus metrics (optional) |

3. **Outbound Rules:**

   | Type | Port | Destination | Description |
   |------|------|-------------|-------------|
   | Custom TCP | 1433 | 0.0.0.0/0 | Azure SQL |
   | Custom TCP | 11000-11999 | 0.0.0.0/0 | Azure SQL redirect ports |
   | HTTPS | 443 | 0.0.0.0/0 | Package updates |
   | All traffic | All | 0.0.0.0/0 | (or restrict to above) |

---

## Step 3: Launch EC2 Instance

1. **AWS Console → EC2 → Launch Instance**

   | Setting | Value |
   |---------|-------|
   | Name | `tailsqlproxy` |
   | AMI | Ubuntu 24.04 LTS ARM64 (search "ubuntu 24.04 arm64") |
   | Instance type | `t4g.xlarge` (4 vCPU, 16 GB) or `c7g.large` (2 vCPU, 4 GB) for lighter load |
   | Key pair | Create new or use existing `.pem` key |
   | Network | `tailsqlproxy-vpc` |
   | Subnet | `tailsqlproxy-subnet` |
   | Auto-assign public IP | Disable (we'll use Elastic IPs) |
   | Security group | `tailsqlproxy-sg` |
   | Storage | 30 GB gp3 |

2. **After launch**, note the instance ID.

---

## Step 4: Assign Secondary Private IPs

1. **AWS Console → EC2 → Network Interfaces**
2. Select the ENI attached to your instance
3. **Actions → Manage IP Addresses**
4. Click **"Assign new IP address"** four times to add 4 secondary private IPs
   - AWS will auto-assign from the subnet (e.g., `10.0.1.11`, `10.0.1.12`, `10.0.1.13`, `10.0.1.14`)
   - Or specify manually
5. Click **Save**
6. Note all 5 private IPs (1 primary + 4 secondary)

---

## Step 5: Allocate and Associate Elastic IPs

1. **AWS Console → EC2 → Elastic IPs → Allocate Elastic IP address** (repeat 5 times)
   - Tag each: `db01`, `db02`, `db03`, `db04`, `db05`

2. **Associate each EIP with a private IP:**
   - Select EIP → **Actions → Associate Elastic IP address**
   - Resource type: Network interface
   - Network interface: select the ENI
   - Private IP address: select the corresponding private IP
   - Repeat for all 5

3. **Record the mapping:**

   | Instance | Private IP | Elastic IP | Target Azure SQL |
   |----------|-----------|------------|------------------|
   | db01  | 10.0.1.10 | EIP-1      | example-db01.database.windows.net |
   | db02    | 10.0.1.11 | EIP-2      | example-db02.database.windows.net |
   | db03    | 10.0.1.12 | EIP-3      | example-db03.database.windows.net |
   | db04   | 10.0.1.13 | EIP-4      | example-db04.database.windows.net |
   | db05   | 10.0.1.14 | EIP-5      | example-db05.database.windows.net |

---

## Step 6: Configure OS Networking

SSH into the instance and configure the secondary IPs:

```bash
ssh -i your-key.pem ubuntu@<any-EIP>
```

### Enable secondary IPs via netplan

```bash
# Find the network interface name
ip link show   # usually "ens5" on AWS

sudo tee /etc/netplan/51-secondary-ips.yaml << 'EOF'
network:
  version: 2
  ethernets:
    ens5:
      addresses:
        - 10.0.1.11/24
        - 10.0.1.12/24
        - 10.0.1.13/24
        - 10.0.1.14/24
EOF

sudo netplan apply
```

### Verify all IPs are active

```bash
ip addr show ens5 | grep inet
# Should show all 5 IPs (primary + 4 secondary)
```

---

## Step 7: Install .NET Runtime and Deploy Proxy

```bash
# Add Microsoft package feed
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
sudo ./dotnet-install.sh --channel 10.0 --runtime dotnet --install-dir /usr/share/dotnet
sudo ln -sf /usr/share/dotnet/dotnet /usr/bin/dotnet
dotnet --info

# Create service user
sudo useradd --system --shell /usr/sbin/nologin tdsproxy

# Create proxy directory
sudo mkdir -p /opt/tailsqlproxy
sudo mkdir -p /var/log/tailsqlproxy/{db01,db02,db03,db04,db05}
sudo chown -R tdsproxy:tdsproxy /opt/tailsqlproxy /var/log/tailsqlproxy
```

### Upload the published binary (from your local machine)

```bash
# On your local machine:
dotnet publish src/TailSqlProxy -c Release -r linux-arm64 --self-contained true -o ./publish
scp -i your-key.pem -r ./publish/* ubuntu@<EIP>:/tmp/tailsqlproxy-deploy/

# On the EC2 instance:
sudo cp -r /tmp/tailsqlproxy-deploy/* /opt/tailsqlproxy/
sudo chown -R tdsproxy:tdsproxy /opt/tailsqlproxy
sudo setcap cap_net_bind_service=+ep /opt/tailsqlproxy/TailSqlProxy
```

---

## Step 8: Create Instance Configuration

### appsettings.json (shared base config)

The `appsettings.json` in `/opt/tailsqlproxy/` is the shared base. Instance-specific values are overridden via environment files.

### Create environment files for each instance

```bash
# db01
sudo tee /etc/tailsqlproxy/db01.env << 'EOF'
Proxy__ListenAddress=10.0.1.10
TargetServer__Host=example-db01.database.windows.net
Proxy__AuditLogPath=/var/log/tailsqlproxy/db01/audit-.log
Proxy__AuditJsonLogPath=/var/log/tailsqlproxy/db01/audit-json-.log
Metrics__Port=9090
EOF

# db02
sudo tee /etc/tailsqlproxy/db02.env << 'EOF'
Proxy__ListenAddress=10.0.1.11
TargetServer__Host=example-db02.database.windows.net
Proxy__AuditLogPath=/var/log/tailsqlproxy/db02/audit-.log
Proxy__AuditJsonLogPath=/var/log/tailsqlproxy/db02/audit-json-.log
Metrics__Port=9091
EOF

# db03
sudo tee /etc/tailsqlproxy/db03.env << 'EOF'
Proxy__ListenAddress=10.0.1.12
TargetServer__Host=example-db03.database.windows.net
Proxy__AuditLogPath=/var/log/tailsqlproxy/db03/audit-.log
Proxy__AuditJsonLogPath=/var/log/tailsqlproxy/db03/audit-json-.log
Metrics__Port=9092
EOF

# db04
sudo tee /etc/tailsqlproxy/db04.env << 'EOF'
Proxy__ListenAddress=10.0.1.13
TargetServer__Host=example-db04.database.windows.net
Proxy__AuditLogPath=/var/log/tailsqlproxy/db04/audit-.log
Proxy__AuditJsonLogPath=/var/log/tailsqlproxy/db04/audit-json-.log
Metrics__Port=9093
EOF

# db05
sudo tee /etc/tailsqlproxy/db05.env << 'EOF'
Proxy__ListenAddress=10.0.1.14
TargetServer__Host=example-db05.database.windows.net
Proxy__AuditLogPath=/var/log/tailsqlproxy/db05/audit-.log
Proxy__AuditJsonLogPath=/var/log/tailsqlproxy/db05/audit-json-.log
Metrics__Port=9094
EOF

sudo chmod 600 /etc/tailsqlproxy/*.env
sudo chown tdsproxy:tdsproxy /etc/tailsqlproxy/*.env
```

---

## Step 9: Create systemd Template Service

```bash
sudo tee /etc/systemd/system/tailsqlproxy@.service << 'EOF'
[Unit]
Description=TailSqlProxy instance %i
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=tdsproxy
Group=tdsproxy
WorkingDirectory=/opt/tailsqlproxy
EnvironmentFile=/etc/tailsqlproxy/%i.env
ExecStart=/opt/tailsqlproxy/TailSqlProxy
Restart=on-failure
RestartSec=5
Environment=DOTNET_ENVIRONMENT=Production
Environment=DOTNET_CLI_HOME=/tmp

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/tailsqlproxy
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
```

---

## Step 10: Start and Enable All Instances

```bash
# Start all instances
sudo systemctl start tailsqlproxy@db01
sudo systemctl start tailsqlproxy@db02
sudo systemctl start tailsqlproxy@db03
sudo systemctl start tailsqlproxy@db04
sudo systemctl start tailsqlproxy@db05

# Enable auto-start on boot
sudo systemctl enable tailsqlproxy@db01
sudo systemctl enable tailsqlproxy@db02
sudo systemctl enable tailsqlproxy@db03
sudo systemctl enable tailsqlproxy@db04
sudo systemctl enable tailsqlproxy@db05

# Verify all listening
sudo ss -tlnp | grep 1433
# Should show 5 entries, each on a different IP
```

---

## Step 11: Update DNS Records

Update your DNS zone (e.g., Cloudflare, Route53) to point to the new Elastic IPs:

| Name | Type | TTL | Value |
|------|------|-----|-------|
| db.db01 | A | 3600 | EIP-1 |
| db.db02 | A | 3600 | EIP-2 |
| db.db03 | A | 3600 | EIP-3 |
| db.db04 | A | 3600 | EIP-4 |
| db.db05 | A | 3600 | EIP-5 |

---

## Step 12: Update Azure SQL Firewall Rules

Add each Elastic IP to the corresponding Azure SQL Server's firewall:

1. **Azure Portal → SQL Server → Networking → Firewall rules**
2. Add a rule for each EIP:

   | Azure SQL Server | Firewall rule IP |
   |------------------|------------------|
   | example-db01 | EIP-1 |
   | example-db02 | EIP-2 |
   | example-db03 | EIP-3 |
   | example-db04 | EIP-4 |
   | example-db05 | EIP-5 |

   **Note:** Since the EC2 instance is outside Azure, Azure SQL uses **Proxy connection policy** automatically — no routing redirect issues.

---

## Step 13: Verify

```bash
# Check all instances are running
for inst in db01 db02 db03 db04 db05; do
  echo "=== $inst ==="
  systemctl is-active tailsqlproxy@$inst
done

# Check listening ports
sudo ss -tlnp | grep 1433

# Check logs
sudo journalctl -u tailsqlproxy@db01 --no-pager -n 10

# Test connectivity from your machine
# (after DNS propagation)
sqlcmd -S db.db01.example.com -U <user> -P '<password>' -Q "SELECT 1"
```

---

## Step 14: Log Retention (optional)

Serilog rolls audit logs daily but never deletes them, so `/var/log/tailsqlproxy/` will grow without bound. The repo ships an example retention job under `scripts/` — a shell script plus a systemd service + timer pair. You can use it as-is or as a template for your own policy.

The example defaults are tunable via env vars: `COMPRESS_AFTER_DAYS` (gzip files older than N days) and `DELETE_AFTER_DAYS` (delete files older than N days). Pick values that match your audit/compliance window.

```bash
# From the build machine — copy the three files up
scp -i your-key.pem \
    scripts/tailsqlproxy-log-cleanup.sh \
    scripts/tailsqlproxy-log-cleanup.service \
    scripts/tailsqlproxy-log-cleanup.timer \
    ec2-user@<EIP>:/tmp/

# On the EC2 instance — install + enable
sudo install -m 0755 -o root -g root /tmp/tailsqlproxy-log-cleanup.sh      /usr/local/sbin/
sudo install -m 0644 -o root -g root /tmp/tailsqlproxy-log-cleanup.service /etc/systemd/system/
sudo install -m 0644 -o root -g root /tmp/tailsqlproxy-log-cleanup.timer  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tailsqlproxy-log-cleanup.timer
```

Verify:

```bash
systemctl list-timers tailsqlproxy-log-cleanup.timer
sudo journalctl -u tailsqlproxy-log-cleanup.service
```

The timer's schedule and retention thresholds are example values — review the unit and script and adjust them to match your operational requirements before deploying.

journald (the Console sink output) is managed separately by `/etc/systemd/journald.conf` (e.g. `SystemMaxUse=200M`) if disk pressure is a concern.

---

## Updating the Proxy

```bash
# On your local machine:
dotnet publish src/TailSqlProxy -c Release -r linux-arm64 --self-contained true -o ./publish
scp -i your-key.pem ./publish/TailSqlProxy.dll ubuntu@<EIP>:/tmp/

# On the EC2 instance:
sudo systemctl stop tailsqlproxy@db01 tailsqlproxy@db02 tailsqlproxy@db03 tailsqlproxy@db04 tailsqlproxy@db05
sudo cp /tmp/TailSqlProxy.dll /opt/tailsqlproxy/
sudo chown tdsproxy:tdsproxy /opt/tailsqlproxy/TailSqlProxy.dll
sudo setcap cap_net_bind_service=+ep /opt/tailsqlproxy/TailSqlProxy
sudo systemctl start tailsqlproxy@db01 tailsqlproxy@db02 tailsqlproxy@db03 tailsqlproxy@db04 tailsqlproxy@db05
```

---

## Cost Estimate (Singapore region, monthly)

| Resource | Cost |
|----------|------|
| EC2 t4g.xlarge (4 vCPU, 16 GB) | ~$98 |
| 5 Elastic IPs (attached) | Free (attached to running instance) |
| 30 GB gp3 EBS | ~$2.40 |
| Data transfer (first 100 GB) | Free |
| Data transfer (per GB after) | ~$0.12/GB |
| **Total** | **~$100/month** |

Compared to Azure D4s_v5: ~$140/month. AWS Graviton is ~30% cheaper for ARM64 workloads.
