<p align="center">
  <img src="./corporate_infographics.png" alt="Gort Firewall Enterprise Architecture" width="850">
</p>

# 🤖 GORT: Autonomous Linux Endpoint Firewall, Zero-Trust Sentinel & AI Copilot

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(ProcFS%20%2B%20Netfilter)-orange.svg)]()
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)]()
[![UI: Textual TUI](https://img.shields.io/badge/UI-Textual%20(Modular%20TUI)-cyan.svg)]()
[![Zero-Trust: Embedded Engine](https://img.shields.io/badge/Security-Zero--Trust%20Monitor-brightgreen.svg)]()
[![Autonomous Defense: Active Sentinel](https://img.shields.io/badge/Defense-Autonomous%20Sentinel%20%26%20Bad%20USB-red.svg)]()
[![AI: Antigravity SDK & Gemini](https://img.shields.io/badge/AI-Google%20Antigravity%20SDK-purple.svg)]()

> *"Klaatu barada nikto"* — Named after the silent, indestructible robotic guardian from *The Day the Earth Stood Still*, **Gort** is an autonomous, non-rolling terminal network inspector, Zero-Trust security monitor, Bad USB threat sentinel, and kernel-level Netfilter packet filtering engine for Linux workstations, servers, and cloud endpoints.

Gort combines low-level Linux Kernel socket telemetry with a **Zero-Trust scoring engine (0-100)**, an **Autonomous Sentinel** for neutralizing reverse shells and Bad USB hardware injectors without false positives, and an embedded **Google Antigravity / Gemini AI Copilot** that translates complex network telemetry into plain English.

---

## ⚡ Quick Start (One-Command Launch)

Use the universal launcher script [run.sh](file:///home/aug20/myfirewall-linux/run.sh) (or `./gort.sh`) to automatically configure dependencies and launch the dashboard:

```bash
# 1. Clone the repository
git clone https://github.com/dparksports/gort-firewall.git
cd gort-firewall

# 2. Launch in Active Security Mode (Netfilter Kernel Blocking + AI + Autonomous Sentinel)
sudo ./run.sh

# 3. Or launch in Monitor-Only Safe Mode (No root required)
./run.sh --mock
```

---

## ✨ Key Capabilities

| Feature | Description |
|---|---|
| **🛡️ Autonomous Sentinel & Bad USB Defense** | Automatically detects reverse shells (`bash -i /dev/tcp`), Bad USB keystroke injection gadgets, and dropper beacons. Neutralizes threats via graduated **`SIGSTOP` freeze** or **`SIGKILL` + Netfilter drop**. |
| **↩️ 1-Click Incident Rollback (`U`)** | Instant, zero-friction restoration modal: sends `SIGCONT` to unfreeze processes, lifts temporary firewall drops, and records user overrides. |
| **🛡️ Zero-Trust Security Monitor** | Continuously verifies every connection with a dynamic **Trust Score (0-100)**, Micro-segmentation Zones (1-5), and heuristic anomaly detectors. |
| **🤖 Antigravity AI Security Advisor** | Press **`E`** to receive an instant, plain-English breakdown of any connection powered by **Google Gemini** via the Antigravity Python SDK (`google.antigravity`). |
| **💬 Interactive "Ask Gort" Copilot** | Press **`A`** or **`Space`** to ask the embedded AI copilot questions in natural language: *"Is my connection secure?"*, *"Why is Chrome connecting to this IP?"*, *"Will blocking this break my app?"*. |
| **🖥️ Non-Rolling Modular Textual TUI** | Built with **Textual**. Employs alternate screen buffers with full keyboard (`↑`/`↓`, `PgUp`/`PgDn`) and mouse scrolling. Pure modular design (`ui_modals.py`, `ui_helpers.py`, `myfirewall2.py`). |
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
| **`U`** | **Unfreeze / Rollback** | Opens 1-click incident rollback dialog to restore paused processes & lift drops. |
| **`B`** | **Block / Unblock IP** | Opens modal pre-populated with highlighted IP to toggle kernel drop. |
| **`I`** | **Ignore Process / IP** | Opens modal to hide trusted applications from the feed. |
| **`/`** | **Search & Filter** | Focuses the live search bar for multi-field filtering. |
| **`Esc`** | **Clear Filter / Focus** | Clears the active filter query and returns focus to the table. |
| **`1` – `7`** | **Switch Tabs** | `1` All \| `2` Outbound \| `3` Inbound \| `4` Zero-Trust \| `5` Auto-Defense \| `6` Blocked \| `7` Ignored |
| **`R`** | **Reload Config** | Reloads saved firewall rules and ignore policies from disk. |
| **`H` / `?`** | **Help Dialog** | Opens interactive keyboard shortcuts guide. |
| **`Q` / `Ctrl+C`** | **Quit** | Gracefully terminates background monitors and flushes audit logs. |

---

## 🛡️ Graduated Autonomous Action Ladder

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      GRADUATED ACTION LADDER                               │
├─────────┬──────────────────────┬───────────────────────────────────────────┤
│ TIER 0  │ Confidence < 60%     │ Silent observation & audit log recording  │
├─────────┼──────────────────────┼───────────────────────────────────────────┤
│ TIER 1  │ Confidence 60% – 79% │ Soft alert & bandwidth micro-throttling   │
├─────────┼──────────────────────┼───────────────────────────────────────────┤
│ TIER 2  │ Confidence 80% – 94% │ Non-destructive SIGSTOP freeze + 15m TTL  │
├─────────┼──────────────────────┼───────────────────────────────────────────┤
│ TIER 3  │ Confidence >= 95%    │ SIGKILL + Permanent Netfilter Kernel Drop │
└─────────┴──────────────────────┴───────────────────────────────────────────┘
```

For complete technical specifications, read [BAD_USB_AND_AUTONOMOUS_DEFENSE.md](file:///home/aug20/myfirewall-linux/BAD_USB_AND_AUTONOMOUS_DEFENSE.md) and [AUTONOMOUS_DEFENSE_PLAN.md](file:///home/aug20/myfirewall-linux/AUTONOMOUS_DEFENSE_PLAN.md).

---

## 🚀 Launcher Script Options

The [run.sh](file:///home/aug20/myfirewall-linux/run.sh) script handles virtual environment detection, dependencies, and execution modes:

```text
Usage: ./run.sh [OPTIONS]

Options:
  -s, --security     Run in active firewall mode with root (sudo required)
  -m, --mock         Run in safe/monitor-only mode (no root required)
  -i, --install      Install/update all required dependencies in venv
  -t, --test         Run automated unit test suite (including Zero-Trust & Sentinel)
  -h, --help         Display help message and exit
```

---

## 🧪 Automated Testing

Execute the comprehensive automated test suite (all 6 modules):

```bash
./run.sh --test
```

---

## 📂 Repository Structure

```text
gort-firewall/
├── run.sh                          # Universal launcher & environment manager
├── gort.sh                         # Gort execution entrypoint alias
├── myfirewall2.py                  # Main Textual TUI frontend controller (~340 lines)
├── ui_modals.py                    # Interactive modal screens (Block, Ignore, AI, Copilot, Rollback, Help)
├── ui_helpers.py                   # UI formatting & string presentation utilities
├── autonomous_sentinel.py          # Autonomous Intrusion Detector, Bad USB & Rollback Engine
├── zero_trust_engine.py            # Zero-Trust scoring, micro-segmentation & anomaly heuristics
├── ai_advisor.py                   # Google Antigravity SDK & Gemini Copilot advisor
├── myfirewall_core.py              # Core caching, worker threads, and state engine
├── process_resolver.py             # /proc/<PID>/fd socket-to-process mapper
├── firewall_manager.py             # Netfilter iptables packet drop manager
├── BAD_USB_AND_AUTONOMOUS_DEFENSE.md # Complete manual on Bad USB defense & Sentinel operations
├── AUTONOMOUS_DEFENSE_PLAN.md      # Autonomous defense architecture & FP mitigation blueprint
├── IMPLEMENTATION_PLAN.md          # UI and core decoupling refactoring specification
├── DOCUMENTATION.md                # Full technical architecture and operational manual
├── README.md                       # Comprehensive project overview
├── test_autonomous_sentinel.py     # Sentinel & 1-click rollback unit tests
├── test_zero_trust.py              # Zero-Trust engine & AI advisor unit tests
├── test_network_monitor.py         # Socket parser unit tests
├── test_firewall_manager.py        # Netfilter rule unit tests
├── test_connection_history.py      # Audit logger unit tests
└── test_event_monitors.py          # Event queues unit tests
```

---

## 📜 License & Acknowledgments

* **License:** Apache License 2.0.
* **Repository:** [https://github.com/dparksports/gort-firewall](https://github.com/dparksports/gort-firewall)
* **Inspired by:** *Gort* from *The Day the Earth Stood Still* (1951 / 2008).
