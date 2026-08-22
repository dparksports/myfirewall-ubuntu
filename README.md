<p align="center">
  <img src="./corporate_infographics.png" alt="Gort Firewall Enterprise Architecture" width="850">
</p>

# 🤖 GORT: Autonomous Linux Endpoint Firewall, Zero-Trust Monitor & AI Copilot

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(ProcFS%20%2B%20Netfilter)-orange.svg)]()
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)]()
[![UI: Textual TUI](https://img.shields.io/badge/UI-Textual%20(Non--Rolling)-cyan.svg)]()
[![Zero-Trust: Embedded Engine](https://img.shields.io/badge/Security-Zero--Trust%20Monitor-brightgreen.svg)]()
[![AI: Antigravity SDK & Gemini](https://img.shields.io/badge/AI-Google%20Antigravity%20SDK-purple.svg)]()

> *"Klaatu barada nikto"* — Named after the silent, indestructible robotic guardian from *The Day the Earth Stood Still*, **Gort** is an autonomous, non-rolling terminal network inspector, Zero-Trust security monitor, and kernel-level Netfilter packet filtering engine for Linux workstations, servers, and cloud endpoints.

Gort combines low-level Linux Kernel socket telemetry with a **Zero-Trust scoring engine (0-100)**, micro-segmentation trust zones, and an embedded **Google Antigravity / Gemini AI Copilot** that translates complex network telemetry into plain English for non-technical users and security teams.

---

## ⚡ Quick Start (One-Command Launch)

Use the universal launcher script [run.sh](file:///home/aug20/myfirewall-linux/run.sh) (or `./gort.sh`) to automatically configure dependencies and launch the dashboard:

```bash
# 1. Clone the repository
git clone https://github.com/dparksports/gort-firewall.git
cd gort-firewall

# 2. Launch in Active Security Mode (Netfilter Kernel Blocking + AI + Zero-Trust)
sudo ./run.sh

# 3. Or launch in Monitor-Only Safe Mode (No root required)
./run.sh --mock
```

---

## ✨ Key Capabilities

| Feature | Description |
|---|---|
| **🛡️ Zero-Trust Security Monitor** | Continuously verifies every connection with a dynamic **Trust Score (0-100)**, Micro-segmentation Zones (1-5), and heuristic anomaly detectors (`[TEMP_DIR_EXEC]`, `[REVERSE_SHELL_PORT]`, `[NO_REVERSE_DNS]`). |
| **🤖 Antigravity AI Security Advisor** | Press **`E`** to receive an instant, plain-English breakdown of any connection powered by **Google Gemini** via the Antigravity Python SDK (`google.antigravity`). |
| **💬 Interactive "Ask Gort" Copilot** | Press **`A`** or **`Space`** to ask the embedded AI copilot questions in natural language: *"Is my connection secure?"*, *"Why is Chrome connecting to this IP?"*, *"Will blocking this break my app?"*. |
| **🖥️ Non-Rolling Textual TUI** | Built with **Textual**. Uses the terminal alternate screen buffer with full keyboard (`↑`/`↓`, `PgUp`/`PgDn`) and mouse scrolling. Eliminates terminal jitter and rolling lines. |
| **🔎 Deep Process Inspector** | Correlates sockets with process PIDs, full command-line arguments, binary paths, system UID/username, socket inodes, and bidirectional byte/packet rates. |
| **⏱️ 10s Transient Connection Memory** | Retains short-lived tracking beacons and microsecond network bursts on screen for 10 seconds so ephemeral threats cannot hide. |
| **🧱 One-Touch Netfilter Drop** | Press **`B`** to immediately drop an IP with kernel-level `iptables` rules in both `INPUT` and `OUTPUT` chains. |
| **🙈 Process & IP Ignore Rules** | Press **`I`** to hide noisy trusted applications (e.g., Chrome, Discord) or entire subnet CIDRs. |
| **🔍 Instant Live Filter** | Press **`/`** to filter the live stream by process name, remote IP, port, protocol, or hostname in real time. |

---

## ⌨️ Interactive Keyboard Controls

| Shortcut | Action | Description |
|---|---|---|
| **`↑` / `↓` / `Mouse`** | **Navigate / Scroll** | Move cursor through the live connection table. |
| **`PgUp` / `PgDn`** | **Page Scroll** | Fast scroll through dozens of connections without viewport rolling. |
| **`E`** | **Explain with AI** | Opens modal with plain-English safety analysis via Google Antigravity SDK. |
| **`A` / `Space`** | **Ask Gort Copilot** | Opens interactive natural language AI security assistant dialog. |
| **`B`** | **Block / Unblock IP** | Opens modal pre-populated with highlighted IP to toggle kernel drop. |
| **`I`** | **Ignore Process / IP** | Opens modal to hide trusted applications from the feed. |
| **`/`** | **Search & Filter** | Focuses the live search bar for multi-field filtering. |
| **`Esc`** | **Clear Filter / Focus** | Clears the active filter query and returns focus to the table. |
| **`1` – `6`** | **Switch Tabs** | `1` All \| `2` Outbound \| `3` Inbound \| `4` Zero-Trust Alerts \| `5` Blocked \| `6` Ignored |
| **`R`** | **Reload Config** | Reloads saved firewall rules and ignore policies from disk. |
| **`H` / `?`** | **Help Dialog** | Opens interactive keyboard shortcuts guide. |
| **`Q` / `Ctrl+C`** | **Quit** | Gracefully terminates background monitors and flushes audit logs. |

---

## 🛡️ Zero-Trust Security Micro-Segmentation

Gort implements a strict **"Never Trust, Always Verify"** architecture across 5 Network Zones:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ ZONE 1: Intra-Host Loopback (127.0.0.1, IPC, Unix Domain Sockets)          │
│ ZONE 2: Local Area Network Boundary (RFC 1918 Private Subnets)             │
│ ZONE 3: Verified Cloud Infrastructure & CDNs (Google, AWS, Cloudflare)     │
│ ZONE 4: Untrusted Public Internet (External unverified hosts)              │
│ ZONE 5: High-Risk Anomaly / Suspicious Ports & Executable Directories      │
└────────────────────────────────────────────────────────────────────────────┘
```

### Trust Score Breakdown (0–100):
* `🟢 TRUST: 80-100` — Verified core system service or trusted infrastructure.
* `🟡 VERIFY: 50-79` — Unknown application or unverified external IP.
* `🔴 SUSPECT: 25-49` — Ephemeral micro-burst or missing reverse DNS record.
* `🔥 THREAT: 0-24` — High-risk port, script in `/tmp`, or suspicious arguments.

---

## 🚀 Launcher Script Options

The [run.sh](file:///home/aug20/myfirewall-linux/run.sh) script handles virtual environment detection, dependencies, and execution modes:

```text
Usage: ./run.sh [OPTIONS]

Options:
  -s, --security     Run in active firewall mode with root (sudo required)
  -m, --mock         Run in safe/monitor-only mode (no root required)
  -i, --install      Install/update all required dependencies in venv
  -t, --test         Run automated unit test suite (including Zero-Trust tests)
  -h, --help         Display help message and exit
```

---

## 📐 Enterprise Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. LINUX KERNEL SPACE                                                      │
│    • ProcFS Socket Harvester (/proc/net/tcp{,6}, udp{,6}, raw{,6} @ 5Hz)   │
│    • eBPF Tracepoints & Kprobes (Microsecond socket state change queue)    │
│    • Conntrack Netlink Flow Accounting (/proc/net/nf_conntrack)            │
│    • Netfilter iptables Packet Dropping Engine (INPUT / OUTPUT Drop)       │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼──────────────────────────────────────┐
│ 2. CORE INTELLIGENCE & ZERO-TRUST ENGINE                                   │
│    • Zero-Trust Risk Engine: Score (0-100), Micro-segmentation Zones 1-5   │
│    • Process Correlator: Socket Inodes ➔ /proc/<PID>/fd ➔ Exe, Cmdline, User│
│    • Antigravity AI Advisor: Google Gemini integration via SDK             │
│    • Asynchronous Worker Pools: Non-blocking GeoIP & Reverse DNS Queues    │
│    • 10-Second Transient Connection Memory & Decay Cache                   │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼──────────────────────────────────────┐
│ 3. TEXTUAL TUI DASHBOARD LAYER                                             │
│    • Alternate Screen Buffer Virtual DataTable (Zero Scrollback Rolling)   │
│    • Zero-Trust Badging & Anomaly Detection Indicators                     │
│    • Selected Connection Deep Inspector Pane & SHA256 Hash Verification    │
│    • Interactive Modal Dialogs (AI Explain, AI Copilot, Block, Ignore)     │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧪 Automated Testing

Execute the test suite to verify socket parsers, firewall rule managers, Zero-Trust scoring, and AI advisors:

```bash
./run.sh --test
```

---

## 📂 Repository Structure

```text
gort-firewall/
├── run.sh                     # Universal launcher & environment manager
├── gort.sh                    # Gort execution entrypoint alias
├── myfirewall2.py             # Main Textual TUI frontend dashboard
├── myfirewall_core.py         # Core caching, worker threads, and state engine
├── zero_trust_engine.py       # Zero-Trust scoring, micro-segmentation & anomaly heuristics
├── ai_advisor.py              # Google Antigravity SDK & Gemini Copilot advisor
├── network_monitor.py         # ProcFS socket tables scanner
├── process_resolver.py        # /proc/<PID>/fd socket-to-process mapper
├── firewall_manager.py        # Netfilter iptables packet drop manager
├── generate_infographics.py   # Corporate 16:9 architecture infographic generator
├── corporate_infographics.png # Generated architecture infographic asset
├── DOCUMENTATION.md           # Full technical architecture and operational manual
├── README.md                  # Comprehensive project documentation
├── test_zero_trust.py         # Zero-Trust engine & AI advisor unit tests
├── test_network_monitor.py    # Socket parser unit tests
├── test_firewall_manager.py   # Netfilter rule unit tests
├── test_connection_history.py # Audit logger unit tests
└── test_event_monitors.py     # Event queues unit tests
```

---

## 📜 License & Acknowledgments

* **License:** Apache License 2.0.
* **Inspired by:** *Gort* from *The Day the Earth Stood Still* (1951 / 2008).
