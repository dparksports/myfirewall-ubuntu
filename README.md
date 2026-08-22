<p align="center">
  <img src="./corporate_infographics.png" alt="Gort Firewall Enterprise Architecture" width="850">
</p>

# 🤖 GORT: Autonomous Linux Endpoint Firewall & Connection Inspector

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(ProcFS%20%2B%20Netfilter)-orange.svg)]()
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)]()
[![UI: Textual TUI](https://img.shields.io/badge/UI-Textual%20(Non--Rolling)-cyan.svg)]()
[![AI Ready: Gemini Agent](https://img.shields.io/badge/AI-Gemini%20Agent%20Ready-purple.svg)]()

> *"Klaatu barada nikto"* — Named after the silent, indestructible robotic guardian from *The Day the Earth Stood Still*, **Gort** is an autonomous, non-rolling terminal network inspector and kernel-level Netfilter firewall for Linux workstations, servers, and cloud endpoints.

Gort provides real-time visibility into every outbound and inbound connection, identifies the responsible processes and full command arguments, and allows one-touch packet blocking directly via the Linux kernel. **Upcoming Gemini Agent integration** brings autonomous threat analysis, natural-language traffic queries, and automated incident triage directly to your terminal.

---

## ⚡ Quick Start (One-Command Launch)

Use the universal launcher script [run.sh](file:///home/aug20/myfirewall-linux/run.sh) (or `./gort.sh`) to automatically set up dependencies and launch the dashboard:

```bash
# 1. Clone the repository
git clone https://github.com/dparksports/gort-firewall.git
cd gort-firewall

# 2. Launch in Security Mode (Active Kernel Netfilter Blocking - Recommended)
sudo ./run.sh

# 3. Or launch in Monitor-Only Safe Mode (No root required)
./run.sh --mock
```

---

## ✨ Key Capabilities

| Feature | Description |
|---|---|
| **🖥️ Non-Rolling TUI** | Built with **Textual**. Uses the terminal alternate screen buffer with full keyboard (`↑`/`↓`, `PgUp`/`PgDn`) and mouse scrolling. No jitter or rolling lines. |
| **🔎 Deep Process Inspector** | Highlighting any connection instantly displays full command-line arguments, binary path, system UID/username, socket inode, and reverse DNS. |
| **⏱️ 10s Transient Memory** | Retains short-lived tracking beacons and microsecond network bursts on screen for 10 seconds so they cannot hide from view. |
| **🧱 One-Touch Netfilter Drop** | Press **`B`** to immediately drop an IP with kernel-level `iptables` rules in both `INPUT` and `OUTPUT` chains. |
| **🙈 Process & IP Ignore Rules** | Press **`I`** to hide noisy trusted applications (e.g., Chrome, Discord) or entire subnet CIDRs. |
| **🔍 Instant Live Filter** | Press **`/`** to filter the live stream by process name, remote IP, port, protocol, or hostname in real time. |
| **🤖 Gemini AI Integration (Roadmap)** | Natural language network queries, automated domain reputation lookups, and autonomous threat mitigation. |

---

## ⌨️ Interactive Keyboard Controls

| Shortcut | Action | Description |
|---|---|---|
| **`↑` / `↓` / `Mouse`** | **Navigate / Scroll** | Move cursor through the live connection table. |
| **`PgUp` / `PgDn`** | **Page Scroll** | Scroll through dozens of connections without viewport rolling. |
| **`B`** | **Block / Unblock IP** | Opens modal pre-populated with highlighted IP to toggle kernel drop. |
| **`I`** | **Ignore Process / IP** | Opens modal to hide trusted applications from the feed. |
| **`/`** | **Search & Filter** | Focuses the live search bar for multi-field filtering. |
| **`Esc`** | **Clear Filter / Focus** | Clears the active filter query and returns focus to the table. |
| **`1` – `5`** | **Switch Tabs** | `1` All Conns \| `2` Outbound \| `3` Inbound \| `4` Blocked \| `5` Ignored |
| **`R`** | **Reload Config** | Reloads saved firewall rules and ignore policies from disk. |
| **`H` / `?`** | **Help Dialog** | Opens interactive keyboard shortcuts guide. |
| **`Q` / `Ctrl+C`** | **Quit** | Gracefully terminates background monitors and flushes audit logs. |

---

## 🚀 Launcher Script Options

The [run.sh](file:///home/aug20/myfirewall-linux/run.sh) script handles virtual environment detection, dependencies, and execution modes:

```text
Usage: ./run.sh [OPTIONS]

Options:
  -s, --security     Run in active firewall mode with root (sudo required)
  -m, --mock         Run in safe/monitor-only mode (no root required)
  -i, --install      Install/update all required dependencies in venv
  -t, --test         Run automated unit test suite
  -h, --help         Display help message and exit
```

---

## 📐 Enterprise Architecture

Gort operates across three distinct architectural layers:

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
│ 2. CORE INTELLIGENCE & RESOLUTION ENGINE                                   │
│    • Process Correlator: Socket Inodes ➔ /proc/<PID>/fd ➔ Exe, Cmdline, User│
│    • Asynchronous Worker Pools: Non-blocking GeoIP & Reverse DNS Queues    │
│    • 10-Second Transient Connection Memory & Decay Cache                   │
│    • Gemini Security Agent Copilot & Rule Policy Engine                   │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼──────────────────────────────────────┐
│ 3. TEXTUAL TUI DASHBOARD LAYER                                             │
│    • Alternate Screen Buffer Virtual DataTable (Zero Scrollback Rolling)   │
│    • Real-Time Bandwidth & Socket Health Telemetry Meter                   │
│    • Selected Connection Deep Inspector Pane                               │
│    • Interactive Modal Dialogs (Block IP, Ignore Process, Help)            │
└────────────────────────────────────────────────────────────────────────────┘
```

For comprehensive technical specifications, read the full [DOCUMENTATION.md](file:///home/aug20/myfirewall-linux/DOCUMENTATION.md).

---

## 📁 Configuration & Audit Files

All configuration and audit data is persisted automatically in your user home directory:

* **Firewall Rules & Policies:** `~/.config/myfirewall/rules.json`
* **Historical Audit Trail:** `~/.config/myfirewall/connection_history.log` (and `./connection_history.log`)

To inspect active configuration rules:
```bash
python3 -m json.tool ~/.config/myfirewall/rules.json
```

---

## 🧪 Automated Testing

Execute the test suite to verify socket parsers, firewall rule managers, and telemetry caches:

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
├── network_monitor.py         # ProcFS socket parsing core (TCP, UDP, RAW)
├── process_resolver.py        # Inode-to-PID, command-line, and user correlator
├── firewall_manager.py        # Linux Netfilter / iptables interface
├── ebpf_monitor.py            # eBPF kernel event listener
├── conntrack_monitor.py       # Conntrack flow monitor
├── generate_infographics.py   # High-resolution architecture visual generator
├── corporate_infographics.png # Architecture infographic visual
├── DOCUMENTATION.md           # In-depth technical architecture manual
├── README.md                  # Project overview and quick start guide
├── requirements.txt           # Python dependencies (textual, rich, psutil)
└── LICENSE                    # Apache License 2.0
```

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](file:///home/aug20/myfirewall-linux/LICENSE) for details.
