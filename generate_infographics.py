#!/usr/bin/env python3
"""
Generate a corporate-grade architecture infographic for MyFirewall Linux.
Outputs: corporate_infographics.png
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches

def draw_infographic():
    # 1920x1080 style high-res figure (16:9 aspect ratio)
    fig, ax = plt.subplots(figsize=(16, 9), dpi=150)
    fig.patch.set_facecolor('#0b0f19')  # Deep enterprise navy/slate
    ax.set_facecolor('#0b0f19')
    ax.set_xlim(0, 1600)
    ax.set_ylim(0, 900)
    ax.axis('off')

    # Palette
    cyan = '#00e5ff'
    electric_blue = '#2979ff'
    emerald = '#00e676'
    amber = '#ffab00'
    coral = '#ff1744'
    text_white = '#ffffff'
    text_muted = '#90a4ae'
    card_bg = '#131b2e'
    card_border = '#1f2d4d'
    accent_bg = '#1a233a'

    # Title Banner
    ax.text(800, 850, "GORT FIREWALL — ENTERPRISE ARCHITECTURE", fontsize=24, fontweight='bold',
            color=text_white, ha='center', va='center', fontfamily='sans-serif')
    ax.text(800, 820, "Autonomous Linux Kernel Netfilter Threat Mitigation & Textual TUI Engine  •  \"Klaatu barada nikto\"",
            fontsize=12, color=cyan, ha='center', va='center', fontfamily='sans-serif')

    # Sub-banner stats / tags
    tags = ["Zero Rolling / Non-Jitter TUI", "eBPF & ProcFS Sockets", "Netfilter Kernel Drop", "10s Transient Memory"]
    for i, tag in enumerate(tags):
        tx = 320 + i * 320
        badge = patches.FancyBboxPatch((tx - 130, 780), 260, 26, boxstyle="round,pad=3,rounding_size=6",
                                      facecolor='#0f172a', edgecolor=cyan, linewidth=1)
        ax.add_patch(badge)
        ax.text(tx, 793, tag, fontsize=9, fontweight='bold', color=text_white, ha='center', va='center')

    # --- 3 MAIN TIERS ---

    # Column 1: Tier 1 - Kernel Harvesting & Enforcement
    c1_x, c1_y, c1_w, c1_h = 60, 80, 460, 670
    card1 = patches.FancyBboxPatch((c1_x, c1_y), c1_w, c1_h, boxstyle="round,pad=10,rounding_size=12",
                                  facecolor=card_bg, edgecolor=card_border, linewidth=1.5)
    ax.add_patch(card1)
    
    # Tier 1 Header
    t1_header = patches.FancyBboxPatch((c1_x + 15, c1_y + c1_h - 55), c1_w - 30, 42,
                                       boxstyle="round,pad=5,rounding_size=8",
                                       facecolor='#1e293b', edgecolor=coral, linewidth=1.5)
    ax.add_patch(t1_header)
    ax.text(c1_x + c1_w/2, c1_y + c1_h - 34, "1. LINUX KERNEL SPACE", fontsize=13, fontweight='bold',
            color=coral, ha='center', va='center')

    # Tier 1 Modules
    t1_items = [
        ("ProcFS Socket Harvester", "Scans /proc/net/tcp{,6}, udp{,6}, raw{,6}\nat 5Hz frequency for active socket inodes", cyan),
        ("eBPF Event Tracepoints", "Kprobes on inet_sock_set_state & connect\nInstant microsecond connection event queue", electric_blue),
        ("Conntrack Telemetry (/proc/net)", "Extracts bidirectional bytes_sent/recv\nand real-time packet counters per flow", emerald),
        ("Netfilter / iptables Drops", "Kernel-level packet filtering in INPUT & OUTPUT\nInstant zero-overhead IP/CIDR blocking", coral)
    ]
    for i, (heading, desc, color) in enumerate(t1_items):
        by = c1_y + c1_h - 125 - i * 135
        block = patches.FancyBboxPatch((c1_x + 20, by), c1_w - 40, 115, boxstyle="round,pad=6,rounding_size=8",
                                      facecolor=accent_bg, edgecolor=color, linewidth=1.2)
        ax.add_patch(block)
        ax.text(c1_x + 35, by + 90, f"● {heading}", fontsize=11, fontweight='bold', color=color, va='center')
        ax.text(c1_x + 35, by + 45, desc, fontsize=9, color=text_white, va='center', linespacing=1.4)

    # Column 2: Tier 2 - Core Engine & Intelligence
    c2_x, c2_y, c2_w, c2_h = 570, 80, 460, 670
    card2 = patches.FancyBboxPatch((c2_x, c2_y), c2_w, c2_h, boxstyle="round,pad=10,rounding_size=12",
                                  facecolor=card_bg, edgecolor=card_border, linewidth=1.5)
    ax.add_patch(card2)

    # Tier 2 Header
    t2_header = patches.FancyBboxPatch((c2_x + 15, c2_y + c2_h - 55), c2_w - 30, 42,
                                       boxstyle="round,pad=5,rounding_size=8",
                                       facecolor='#1e293b', edgecolor=amber, linewidth=1.5)
    ax.add_patch(t2_header)
    ax.text(c2_x + c2_w/2, c2_y + c2_h - 34, "2. CORE INTELLIGENCE ENGINE", fontsize=13, fontweight='bold',
            color=amber, ha='center', va='center')

    # Tier 2 Modules
    t2_items = [
        ("Zero-Trust Risk Engine", "Continuous score (0-100), Micro-segmentation\nZones 1-5, and heuristic anomaly detection", amber),
        ("Process Resolver & Inode Map", "Maps sockets to /proc/<PID>/fd & status\nExtracts full binary path, cmdline & user", cyan),
        ("Antigravity AI Copilot", "Natural language threat triage & plain English\nflow explanations powered by Google Gemini", emerald),
        ("10s Transient Memory & Audit", "Catches micro-bursts & ephemeral beacons\nFull audit trail in connection_history.log", electric_blue)
    ]
    for i, (heading, desc, color) in enumerate(t2_items):
        by = c2_y + c2_h - 125 - i * 135
        block = patches.FancyBboxPatch((c2_x + 20, by), c2_w - 40, 115, boxstyle="round,pad=6,rounding_size=8",
                                      facecolor=accent_bg, edgecolor=color, linewidth=1.2)
        ax.add_patch(block)
        ax.text(c2_x + 35, by + 90, f"● {heading}", fontsize=11, fontweight='bold', color=color, va='center')
        ax.text(c2_x + 35, by + 45, desc, fontsize=9, color=text_white, va='center', linespacing=1.4)

    # Column 3: Tier 3 - Textual TUI & User Experience
    c3_x, c3_y, c3_w, c3_h = 1080, 80, 460, 670
    card3 = patches.FancyBboxPatch((c3_x, c3_y), c3_w, c3_h, boxstyle="round,pad=10,rounding_size=12",
                                  facecolor=card_bg, edgecolor=card_border, linewidth=1.5)
    ax.add_patch(card3)

    # Tier 3 Header
    t3_header = patches.FancyBboxPatch((c3_x + 15, c3_y + c3_h - 55), c3_w - 30, 42,
                                       boxstyle="round,pad=5,rounding_size=8",
                                       facecolor='#1e293b', edgecolor=cyan, linewidth=1.5)
    ax.add_patch(t3_header)
    ax.text(c3_x + c3_w/2, c3_y + c3_h - 34, "3. TEXTUAL TUI DASHBOARD", fontsize=13, fontweight='bold',
            color=cyan, ha='center', va='center')

    # Tier 3 Modules
    t3_items = [
        ("Zero-Trust Risk Badging", "Real-time [TRUST: 95] / [SUSPECT: 30]\nvisual traffic-light indicators in live table", emerald),
        ("One-Key AI Explain ([E])", "Instant plain-English safety breakdown\nfor non-technical users and analysts", cyan),
        ("Interactive Copilot ([A] / [Space])", "Natural language Q&A security assistant\nwith real-time advice and firewall controls", amber),
        ("One-Touch Netfilter Drop ([B])", "Zero-overhead kernel packet drops\nCategory Tabs [1-6], Search [/], Reload [R]", coral)
    ]
    for i, (heading, desc, color) in enumerate(t3_items):
        by = c3_y + c3_h - 125 - i * 135
        block = patches.FancyBboxPatch((c3_x + 20, by), c3_w - 40, 115, boxstyle="round,pad=6,rounding_size=8",
                                      facecolor=accent_bg, edgecolor=color, linewidth=1.2)
        ax.add_patch(block)
        ax.text(c3_x + 35, by + 90, f"● {heading}", fontsize=11, fontweight='bold', color=color, va='center')
        ax.text(c3_x + 35, by + 45, desc, fontsize=9, color=text_white, va='center', linespacing=1.4)

    # Inter-tier Connecting Arrows
    arrow1 = patches.FancyArrowPatch((525, 415), (565, 415), arrowstyle='->,head_width=5,head_length=8',
                                     color=cyan, linewidth=2.5, mutation_scale=15)
    ax.add_patch(arrow1)
    arrow2 = patches.FancyArrowPatch((1035, 415), (1075, 415), arrowstyle='->,head_width=5,head_length=8',
                                     color=cyan, linewidth=2.5, mutation_scale=15)
    ax.add_patch(arrow2)

    # Footer note
    ax.text(800, 35, "Secure Linux Endpoint Defense System • Enterprise Monitoring & Incident Response",
            fontsize=10, color=text_muted, ha='center', va='center')

    plt.tight_layout()
    plt.savefig('corporate_infographics.png', dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("Generated corporate_infographics.png successfully!")

if __name__ == '__main__':
    draw_infographic()
