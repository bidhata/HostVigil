<p align="center">
  <img src="images/logo.png" alt="HostVigil" width="200">
</p>

<h1 align="center">HostVigil</h1>

<p align="center">
  <strong>The ghost in your network. Stealth internal reconnaissance that learns.</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="#stealth-features"><img src="https://img.shields.io/badge/stealth-maximum-black.svg" alt="Stealth: Maximum"></a>
  <a href="#ml-engine"><img src="https://img.shields.io/badge/ML-self--learning-purple.svg" alt="ML: Self-Learning"></a>
  <a href="https://github.com/bidhata/HostVigil/stargazers"><img src="https://img.shields.io/github/stars/bidhata/HostVigil?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-hostvigil">Why HostVigil</a> •
  <a href="#features">Features</a> •
  <a href="#dashboard">Dashboard</a> •
  <a href="#red-team-playbook">Red Team Playbook</a> •
  <a href="#ml-engine">ML Engine</a>
</p>

---

## 🎯 What is HostVigil?

HostVigil is a **self-learning stealth reconnaissance platform** built for red teamers, pentesters, and internal security teams. It continuously maps your internal network, identifies vulnerabilities, and learns what's normal — so it can alert you when something isn't.

**The difference?** It does all of this while remaining invisible to blue team defenses.

```
     You:  "Scan the entire 10.0.0.0/8"
     Nmap: *immediately sets off 47 IDS alerts*
HostVigil: *discovers 2,000 hosts over 3 days, zero alerts triggered*
```

---

## 🚀 Why HostVigil?

| Problem | HostVigil's Answer |
|---------|-------------------|
| Network scanners trigger IDS/IPS alerts | Randomized timing, adaptive throttling, and decoy packets |
| Point-in-time scans miss changes | Continuous daemon mode with ML-powered drift detection |
| Manual recon doesn't scale to /8 networks | Automated pipeline handles millions of IPs |
| Scan results are just lists of ports | ML correlates findings, scores anomalies, classifies exploits |
| No context for prioritization | Red Team view groups findings by attack vector |
| Previous engagement data is lost | Full import/export — carry your intel forward |

---

## ⚡ Quick Start

```bash
git clone https://github.com/bidhata/HostVigil.git
cd HostVigil
python -m venv venv && source venv/bin/activate  # Linux/macOS
# Windows: python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt

# Start the daemon (continuous stealth recon + dashboard)
python run.py daemon
# → Dashboard at http://localhost:5000
```

That's it. HostVigil is now **automatically scanning** your network in continuous cycles — discovery, port scanning, service enumeration, TLS inspection, fingerprinting, and ML analysis all run on a loop with stealth timing. No manual triggering needed.

> **Pipeline order is optimized for fast actionable results:** Discovery (nmap first) → TCP scan → Service enum (low-hanging fruit) → TLS inspection → OS fingerprint → UDP scan → ML analysis.

> **Note:** Nuclei (vulnerability scanning) is intentionally excluded from daemon mode to maintain stealth. Trigger it manually from the dashboard or with `python run.py nuclei` when ready.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HostVigil Engine                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │  Discovery   │───▶│   Scanner    │───▶│  ML Engine   │───▶│  Nuclei  │ │
│  │              │    │              │    │              │    │(manual)  │ │
│  │ • Nmap -sn   │    │ • TCP Stealth│    │ • Anomaly    │    │          │ │
│  │ • ARP Sweep  │    │ • UDP Probes │    │ • Temporal   │    │ • Exploit│ │
│  │ • Passive    │    │ • OS Fingerp.│    │ • Correlation│    │ • Verify │ │
│  │ • mDNS/NBNS │    │ • TLS Inspect│    │ • Feedback   │    │ • Report │ │
│  │ • SNMP/SSDP │    │ • SMB/LDAP   │    │ • Evolution  │    │          │ │
│  │ • DNS Custom │    │ • Service ID │    │ • Drift      │    │          │ │
│  │ • TCP SYN   │    │ • Adaptive   │    │              │    │          │ │
│  │ • DHCP Sniff│    │              │    │              │    │          │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────┘ │
│         │                   │                   │                   │       │
│         ▼                   ▼                   ▼                   ▼       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    SQLite Database (WAL mode)                        │   │
│  │         hosts • ports • vulns • anomalies • TLS • enum              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Web Dashboard (Bootstrap 5)                       │   │
│  │     Overview │ Hosts │ Vulns │ Anomalies │ Red Team │ Scan Control  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔥 Features

### 12 Discovery Techniques

| Technique | Method | Stealth Level |
|-----------|--------|:-------------:|
| **Nmap Discover** | nmap -sn with ICMP/TCP probes (first pass) | ⬛⬛⬜⬜⬜ |
| ARP Sweep *(disabled)* | Batched, randomized, with delays | ⬛⬛⬛⬜⬜ |
| NetBIOS/NBNS | Windows host discovery | ⬛⬛⬛⬜⬜ |
| mDNS Enum | .local service queries | ⬛⬛⬛⬛⬜ |
| SSDP/UPnP | Multicast discovery | ⬛⬛⬛⬛⬜ |
| TCP SYN Ping | Lightweight alive check | ⬛⬛⬛⬜⬜ |
| SNMP Sweep | Community string probes (45s+ delays) | ⬛⬛⬛⬛⬜ |
| DNS Reverse Walk | PTR lookups with heavy jitter | ⬛⬛⬛⬛⬜ |
| Passive Sniff | Zero packets sent — just listens | ⬛⬛⬛⬛⬛ |
| DHCP Passive | Captures DHCP traffic silently | ⬛⬛⬛⬛⬛ |
| Custom DNS | Use internal DNS for zone lookups | ⬛⬛⬛⬛⬜ |

> **Discovery order is optimized for fast results:** nmap runs first (finds hosts in seconds), then fast active techniques (NBNS, mDNS, SSDP, TCP SYN), then slow/passive ones (DNS walk, sniffing) for background enrichment.

### Deep Scanning Suite

| Module | Capabilities |
|--------|-------------|
| **TCP Scanner** | Connect/SYN scan, 1000+ port profiles, adaptive throttle, decoy IPs |
| **UDP Scanner** | DNS, SNMP, NTP, SSDP, mDNS with protocol-specific probes |
| **OS Fingerprint** | Passive (banner/port analysis) + Active (TCP stack probing) |
| **TLS Inspector** | Certificate extraction, weak ciphers, expired certs, protocol version |
| **Service Enum** | SMB null sessions, LDAP anon bind, Redis/Docker/ES no-auth |
| **Nuclei Integration** | Rate-limited vuln scanning with red team classification |
| **Credential Spray** | SSH, RDP, SMB, WinRM, Redis, ES, MySQL, Postgres — 1 attempt/host/hour |
| **AD Integration** | Users, groups, Kerberoastable, AS-REP roastable, trusts |

### 🕵️ Stealth Features

```
┌─────────────────────────────────────────────────────┐
│              EVASION TECHNIQUES                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ⏱️  Randomized Timing     10-45s + jitter          │
│  🎭  Adaptive Throttle     Backs off on RST spikes  │
│  👻  Decoy Packets         Configurable fake sources │
│  📦  Fragmentation         Split packets evade DPI   │
│  🔀  TTL Manipulation      Random hop appearance     │
│  📋  File-Only Logging     Zero console footprint    │
│  🔒  Local Dashboard       127.0.0.1 binding        │
│  🎲  Scan Order Shuffle    No sequential patterns    │
│  ⏰  Time Window           Blend with business hours  │
│  🧠  Conditional Nuclei    Only when triggers hit     │
│  📊  Traffic Budgeting     Daily packet limits        │
│  🎭  Persona Rotation      Different scan profiles    │
│  🍯  Honey Token Detection Skip canaries & traps     │
│  💣  Self-Destruct         Wipe all trace on command  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## 📊 Dashboard

Professional SOC-grade web interface with live updates:

- **Overview** — Network stats, severity charts, recent scan history
- **Hosts** — Full inventory with OS, ports, anomaly flags + search/filter
- **Host Detail** — Drill-down view per IP (ports, vulns, anomalies, TLS)
- **Vulnerabilities** — Nuclei findings sorted by severity with search & filters
- **Anomalies** — ML-detected deviations with confidence scores
- **Red Team** — Exploitable targets grouped by attack vector (RCE, auth bypass, default creds...)
- **Scan Controls** — One-click scan triggers, custom DNS discovery, scheduling, profiles, webhooks
- **Network Map** — Interactive vis.js topology graph colored by risk
- **Attack Paths** — MITRE-mapped attack chains with risk scoring
- **MITRE ATT&CK Heatmap** — Visual coverage of tested techniques across 14 tactics
- **Diff View** — What changed since last scan cycle (new hosts, ports, vulns)
- **Notes** — Engagement journal for tracking findings and decisions

Features:
- 🔄 Auto-refresh with 15s countdown indicator
- 🌓 Dark/light theme toggle (persists across sessions)
- 🔔 Toast notifications on scan completions and new anomalies
- 🔐 Login authentication (default: admin/hostvigil)
- 📥 One-click export (JSON / CSV / ZIP package / Markdown Report)
- 🎯 Feedback buttons to train the ML model
- ⏰ Cron-based scan scheduling from the UI
- 📋 Engagement profiles (save/load config presets)
- 🪝 Webhook configuration (Slack, Discord, Teams)
- 🌐 Bind to all interfaces or localhost only

---

## 🧠 ML Engine — It Gets Smarter

HostVigil's ML isn't a gimmick. It's a **self-improving detection system** that enriches itself through 5 mechanisms:

### How It Learns

```
                    ┌──────────────────┐
                    │   Scan Cycle     │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │  Temporal  │  │  Service   │  │  Network   │
     │  Baseline  │  │ Correlation│  │  Snapshot  │
     │            │  │            │  │            │
     │ Learns per │  │ Learns     │  │ Detects    │
     │ hour/week  │  │ combos     │  │ drift      │
     └────────────┘  └────────────┘  └────────────┘
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌────────────────┐
                    │  Anomaly Score │
                    └────────┬───────┘
                             │
                    ┌────────▼───────┐
                    │  Operator      │
                    │  Feedback      │◄──── You confirm/dismiss
                    └────────┬───────┘
                             │
                    ┌────────▼───────┐
                    │  Supervised    │
                    │  Retraining   │
                    └────────────────┘
```

| Mechanism | What It Does | Impact |
|-----------|-------------|--------|
| **Feedback Loop** | You mark anomalies as true/false positive → trains GradientBoosting | Eliminates noise over time |
| **Temporal Baseline** | Learns what's normal per hour-of-week (168 time slots) | "New port at 3AM Sunday" scores higher |
| **Service Correlation** | Builds co-occurrence matrix of services | Detects unusual combos (port 4444 + port 80 = sus) |
| **Network Evolution** | Tracks host/port/service trends over time | Alerts on 30%+ changes (drift) |
| **Incremental Update** | All above run every cycle — no manual retraining | Gets better passively |

**Cold start?** No problem. Rule-based detection works immediately. ML kicks in after 50+ data points.

---

## 💀 Red Team Playbook

### Phase 1: Silent Mapping (Day 1-3)

```bash
# Start daemon — it will silently map the network + serve the dashboard
python run.py daemon
# → Dashboard at http://localhost:5000
```

HostVigil will automatically discover hosts, scan ports, fingerprint OS, inspect TLS, enumerate services — all with stealth timing in continuous cycles. Zero IDS alerts. No manual triggering needed.

### Phase 2: Intelligence Review (Day 3+)

Open **http://localhost:5000** (already running with daemon) and check:
- 🖥️ All discovered hosts with OS identification
- 🔓 Services with no authentication (Redis, Docker, ES)
- 🔑 SMB null sessions & signing disabled (relay attacks)
- 📜 Expired/self-signed certificates
- 🤖 ML anomalies (new hosts, unusual ports, banner changes)

### Phase 3: Targeted Exploitation

```bash
# Trigger Nuclei only against suspicious targets
python run.py nuclei
```

Or use the dashboard button. Nuclei runs rate-limited with stealth settings against targets flagged by the ML engine.

### Phase 4: Report & Export

```bash
python run.py export --format json     # Machine-readable
python run.py export --format report   # Markdown for clients
python run.py export --format csv      # Spreadsheet-friendly
```

### OpSec Checklist

- [x] Keep `min_delay` at 30+s on SOC-monitored networks
- [x] Use `connect` scan (not SYN) to avoid raw packet detection
- [x] Dashboard on `127.0.0.1` — never expose to network
- [x] Daemon mode excludes Nuclei (too noisy for continuous runs)
- [x] Clear `data/logs/` after engagement
- [x] Import previous engagement data to jumpstart ML baseline
- [x] Rotate `jitter_factor` between sessions

---

## 🔫 Credential Spraying

### Credential Spraying (Stealth)

Built-in slow credential spray — 1 attempt per host per hour to avoid lockouts:
- SSH, RDP, SMB, WinRM, Redis, Elasticsearch, MySQL, PostgreSQL
- Default credential list + custom wordlist support
- Rate-limited and randomized to blend with normal auth failures

---

## 🌐 Network Graph

Interactive **vis.js network map** on the dashboard visualizes your entire network topology in real-time:
- Nodes colored by vulnerability severity (green → red)
- Node size scales with open port count
- Hosts grouped by subnet with automatic clustering
- Click any node to drill into host details, ports, and findings
- Hover for quick stats (IP, OS, port count, vuln count)

Access it from the dashboard navigation: **http://localhost:5000/network-graph**

---

## 🔌 Plugin System

Extend HostVigil by dropping Python files in `plugins/`:

```python
# plugins/my_scanner.py
from hostvigil.plugins import ScannerPlugin

class MyCustomScanner(ScannerPlugin):
    name = 'my_scanner'
    description = 'Custom port scanner'
    
    def scan(self, hosts, config):
        # Your logic here
        return [{'ip': '10.0.0.1', 'port': 8080, 'state': 'open', 'service': 'HTTP'}]
```

Plugin types: `DiscoveryPlugin`, `ScannerPlugin`, `AnalysisPlugin`

---

## 🐳 Docker

```bash
docker-compose up -d
# Dashboard at http://localhost:5000
# Scanner runs automatically in daemon mode
```

---

## 🛠️ All Commands

```bash
# ─── Discovery & Scanning ────────────────────────
python run.py discover        # 12 discovery techniques
python run.py scan            # TCP port scanning
python run.py udpscan         # UDP port scanning
python run.py fingerprint     # OS identification
python run.py tls             # TLS/SSL inspection
python run.py enumerate       # SMB/LDAP/Redis/Docker/ES

# ─── Analysis & Exploitation ─────────────────────
python run.py analyze         # ML anomaly detection
python run.py nuclei          # Vulnerability scanning (manual trigger)

# ─── Pipeline Modes ──────────────────────────────
python run.py full            # Single full pipeline run
python run.py daemon          # Continuous background recon + dashboard (no Nuclei)
python run.py kill            # Kill a running daemon process
python run.py wipe            # Self-destruct: securely wipe ALL data
python run.py wipe --force    # Skip confirmation
python run.py wipe --secure   # Zero-fill before delete (paranoid)

# ─── Interface ────────────────────────────────────
python run.py dashboard       # Web UI (default: 127.0.0.1:5000)
python run.py dashboard --host 0.0.0.0 --port 8080

# ─── Data Management ─────────────────────────────
python run.py export --format json     # Full JSON export
python run.py export --format csv      # CSV per table
python run.py export --format report   # Markdown report
python run.py export --format ips      # Plain IP list (for nmap -iL)
python run.py export --format targets  # ip:port list (for nuclei -l)
python run.py export --format urls     # HTTP URLs (for httpx -l)
python run.py export --format c2       # All C2 formats (CS/MSF/Sliver/nmap)
python run.py import data.json --mode merge
python run.py import data.json --mode replace

# ─── Analysis Tools ──────────────────────────────
python run.py diff --hours 24          # What changed in last 24h
python run.py init                     # Interactive config wizard

# ─── Status ──────────────────────────────────────
python run.py status
python run.py status --json

# ─── Options ─────────────────────────────────────
python run.py -c custom_config.yaml daemon   # Custom config
python run.py -v full                        # Verbose (reduces stealth)
```

---

## ⚙️ Configuration

```yaml
hostvigil:
  stealth:
    min_delay: 10.0              # Seconds between probes (raise for stealth)
    max_delay: 45.0              # Maximum randomized delay
    jitter_factor: 0.3           # Timing randomization (0-1)
    decoy_ips: ['10.0.0.1', '10.0.0.254', '172.16.0.1', '192.168.1.1', '100.64.0.1', '198.18.0.1']
    packet_fragmentation: true   # Fragment packets to evade DPI
    ttl_manipulation: true       # Random TTL values
    scan_window_enabled: false   # Only scan during business hours
    scan_window_start: 8         # 8 AM (blends with normal traffic)
    scan_window_end: 18          # 6 PM

  discovery:
    target_ranges:
      - '10.0.0.0/8'
      - '100.64.0.0/10'
      - '172.16.0.0/12'
      - '192.0.0.0/24'
      - '192.168.0.0/16'
      - '198.18.0.0/15'
      - 'fe80::/10'
      - 'fc00::/7'
    techniques:                  # Ordered: fast first, slow last
      - nmap_discover            # nmap -sn (finds hosts in seconds)
      # - arp_sweep              # Disabled: redundant with nmap, extremely slow on large subnets
      - nbns_query
      - mdns_enum
      - ssdp_discover
      - tcp_syn_discover
      - snmp_sweep
      - dns_reverse_walk
      - passive_sniff
      - dhcp_passive
      # - dns_custom            # PTR lookups via internal DNS (set dns_custom_server)
    # nmap host-discovery options
    nmap_timing: 'T4'
    nmap_extra_args: ['-PE', '-PS22,80,135,139,443,445,3389,5985', '-PU137', '--min-rate', '5000', '--max-retries', '1', '-n']
    nmap_disable_arp_ping: false # true on Windows if nmap 7.80 crashes
    nmap_parallel_chunks: 4     # Parallel nmap processes (1=stealth, 4+=fast)
    # Custom DNS discovery
    dns_custom_server: ''       # Internal DNS server IP (empty=disabled)
    dns_custom_domain: ''       # Domain for zone transfer attempts

  scanner:
    scan_type: 'connect'         # 'connect' or 'syn' (syn = root required)
    port_profile: 'standard'     # quick / standard / full / top1000
    udp_scan_enabled: true

  nuclei:
    severity_filter: ['critical', 'high', 'medium']
    rate_limit: 10
    concurrency: 2

  scheduler:
    discovery_interval_hours: 4
    scan_interval_hours: 2
    service_enum_interval_hours: 8
    tls_inspection_interval_hours: 12
    os_fingerprint_interval_hours: 12
    nuclei_interval_hours: 6

  dashboard:
    host: '127.0.0.1'           # Lock to localhost for stealth
    port: 5000
```

---

## 📁 Project Structure

```
HostVigil/
├── run.py                          # CLI entry point (17+ commands)
├── config.yaml                     # All configuration
├── requirements.txt                # Dependencies (pinned)
├── Dockerfile                      # Container build
├── docker-compose.yml              # One-command deployment
├── .gitignore                      # Git ignore rules
├── images/
│   └── logo.png                    # Project logo
├── plugins/                        # Drop-in plugin directory
│   └── example_plugin.py           # Example scanner plugin
├── hostvigil/
│   ├── __init__.py
│   ├── orchestrator.py             # Pipeline coordinator & scheduler
│   ├── config.py                   # YAML config with defaults
│   ├── utils.py                    # DB init, logging, helpers
│   ├── export_import.py            # JSON/CSV export & import
│   ├── alerting.py                 # Webhook notifications (Slack, Discord, Teams)
│   ├── attack_paths.py            # Attack path analysis & graph generation
│   ├── c2_export.py                # C2 framework export (CS/MSF/Sliver/nmap)
│   ├── pcap_export.py              # Packet capture export
│   ├── plugins.py                  # Plugin architecture
│   ├── report_generator.py         # PDF/HTML report generation
│   ├── scheduler.py                # Cron-based scheduling
│   ├── discovery/
│   │   └── stealth_discovery.py    # 12 discovery techniques
│   ├── scanner/
│   │   ├── stealth_scanner.py      # TCP/UDP scanning + adaptive throttle
│   │   ├── os_fingerprint.py       # OS identification
│   │   ├── tls_inspector.py        # Certificate & cipher analysis
│   │   ├── service_enum.py         # SMB/LDAP/Redis/Docker enumeration
│   │   ├── credential_spray.py     # Stealth credential spraying
│   │   ├── ad_integration.py       # Active Directory enumeration
│   │   └── scan_diff.py            # Network change detection
│   ├── ml_engine/
│   │   ├── anomaly_detector.py     # IsolationForest + rule-based detection
│   │   └── enrichment.py           # Feedback loop, temporal, correlations
│   ├── nuclei/
│   │   └── nuclei_runner.py        # Rate-limited vulnerability scanning
│   └── dashboard/
│       ├── app.py                  # Flask app factory + API endpoints
│       ├── templates/              # Porto Admin light theme (Bootstrap 5)
│       └── static/                 # CSS, assets
└── data/                           # Runtime data (gitignored)
    ├── logs/                       # File-only stealth logs
    ├── models/                     # ML model artifacts
    ├── scans/                      # Raw scan data
    └── reports/                    # Generated exports
```

---

## 🔧 Installation

### Requirements

- Python 3.11+
- [Nmap](https://nmap.org/download.html) in PATH (primary host discovery engine)
- Admin/root for ARP sweep and SYN scan (optional — connect scan works without)
- [Nuclei](https://github.com/projectdiscovery/nuclei/releases) binary in PATH (optional)

### Install

```bash
git clone https://github.com/bidhata/HostVigil.git
cd HostVigil
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Dependencies

```
flask==3.1.1
scapy==2.6.1
scikit-learn==1.6.1
numpy==2.2.6
pyyaml==6.0.2
APScheduler==3.11.0
```

All pinned. No bloat. No telemetry. No cloud dependencies.

---

## 🤝 Contributing

PRs welcome. Please ensure:
- Stealth principles maintained (no noisy operations in default config)
- Tests pass
- No new external dependencies without justification

---

## ⚠️ Legal Disclaimer

> **This tool is designed exclusively for authorized internal security assessments.**
>
> Unauthorized use against networks you do not own or have explicit written permission to test is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.
>
> Users are solely responsible for compliance with applicable laws and organizational policies. The author assumes no liability for misuse.
>
> Always obtain written authorization before running HostVigil on any network.

---

## 📜 License

MIT — For authorized use only.

---

## 👤 Author

<table>
  <tr>
    <td>
      <strong>Krishnendu Paul</strong><br>
      <a href="https://github.com/bidhata">@bidhata</a><br><br>
      🌐 <a href="https://krishnendu.com">krishnendu.com</a><br>
      🐙 <a href="https://github.com/bidhata/HostVigil">GitHub</a><br>
      📧 <a href="mailto:me@krishnendu.com">me@krishnendu.com</a>
    </td>
  </tr>
</table>

---

<p align="center">
  <strong>If HostVigil helps your security assessments, drop a ⭐</strong><br>
  <sub>Built for the red team. Invisible to the blue team.</sub>
</p>
