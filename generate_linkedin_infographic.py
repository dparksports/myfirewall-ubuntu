#!/usr/bin/env python3
"""
Generate a professional-grade LinkedIn Infographic for Gort Firewall.
Outputs: linkedin_infographic.png (1920x1080, 16:9 4K-ready presentation asset)
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches

def draw_linkedin_infographic():
    # 1920x1080 16:9 ultra-high clarity layout
    fig, ax = plt.subplots(figsize=(16, 9), dpi=150)
    fig.patch.set_facecolor('#070b16')  # Ultra dark obsidian
    ax.set_facecolor('#070b16')
    ax.set_xlim(0, 1600)
    ax.set_ylim(0, 900)
    ax.axis('off')

    # Color System
    cyan = '#00f0ff'
    neon_blue = '#2979ff'
    emerald = '#00e676'
    amber = '#ffab00'
    coral = '#ff1744'
    purple = '#d500f9'
    text_white = '#ffffff'
    text_sub = '#cfd8dc'
    text_muted = '#78909c'
    card_bg = '#0e1628'
    card_border = '#1c2d4a'
    card_inner = '#141e34'

    # --- TOP BRANDING HEADER ---
    # Top Accent Glow Line
    ax.plot([100, 1500], [875, 875], color=cyan, linewidth=2, alpha=0.8)

    # Main Logo / Title
    ax.text(800, 835, "GORT FIREWALL", fontsize=28, fontweight='bold',
            color=text_white, ha='center', va='center', fontfamily='sans-serif')
    ax.text(800, 798, "Autonomous Linux Endpoint Defense  •  Zero-Trust Sentinel  •  Google Gemini AI",
            fontsize=13, fontweight='bold', color=cyan, ha='center', va='center')

    # Hook Banner (Highlighted Callout)
    hook_box = patches.FancyBboxPatch((200, 740), 1200, 36, boxstyle="round,pad=4,rounding_size=8",
                                     facecolor='#162238', edgecolor=neon_blue, linewidth=1.5)
    ax.add_patch(hook_box)
    ax.text(800, 758, "\"Don't just be suspicious — run this. You never know what's lurking in the background on your Linux machine.\"",
            fontsize=11.5, fontweight='bold', fontstyle='italic', color='#e0f7fa', ha='center', va='center')

    # --- 4 KEY PILLAR CARDS ---
    card_w = 330
    card_h = 515
    y_pos = 195
    spacing = 365
    start_x = 75

    # Card 1: Autonomous Sentinel & Bad USB
    c1_x = start_x + 0 * spacing
    c1 = patches.FancyBboxPatch((c1_x, y_pos), card_w, card_h, boxstyle="round,pad=8,rounding_size=12",
                                facecolor=card_bg, edgecolor=coral, linewidth=1.8)
    ax.add_patch(c1)

    # Header 1
    h1 = patches.FancyBboxPatch((c1_x + 10, y_pos + card_h - 48), card_w - 20, 38,
                                boxstyle="round,pad=4,rounding_size=8",
                                facecolor='#2a121e', edgecolor=coral, linewidth=1.2)
    ax.add_patch(h1)
    ax.text(c1_x + card_w/2, y_pos + card_h - 29, "AUTONOMOUS SENTINEL", fontsize=11, fontweight='bold',
            color='#ff5252', ha='center', va='center')

    c1_bullets = [
        ("Reverse Shell Shield", "Auto-detects bash -i, /dev/tcp, nc -e, python sockets in ms.", coral),
        ("Bad USB Defense", "Trips on Rubber Ducky keystroke bursts & PoisonTap route hijacks.", amber),
        ("Non-Destructive Freeze", "SIGSTOP pauses intruder in RAM without accidental data loss.", cyan),
        ("1-Click Rollback [U]", "Instant restoration with SIGCONT & lifts Netfilter drops.", emerald),
        ("Self-Healing TTL Decay", "15-minute temporary blocks auto-expire if unpinned.", text_sub),
    ]

    for idx, (title, desc, clr) in enumerate(c1_bullets):
        by = y_pos + card_h - 90 - (idx * 84)
        b_box = patches.FancyBboxPatch((c1_x + 12, by - 24), card_w - 24, 62,
                                       boxstyle="round,pad=3,rounding_size=6",
                                       facecolor=card_inner, edgecolor=card_border, linewidth=1)
        ax.add_patch(b_box)
        ax.text(c1_x + 22, by + 18, f">> {title}", fontsize=9.5, fontweight='bold', color=clr)
        ax.text(c1_x + 22, by - 6, desc, fontsize=8, color=text_sub, wrap=True)

    # Card 2: Zero-Trust Continuous Verification
    c2_x = start_x + 1 * spacing
    c2 = patches.FancyBboxPatch((c2_x, y_pos), card_w, card_h, boxstyle="round,pad=8,rounding_size=12",
                                facecolor=card_bg, edgecolor=emerald, linewidth=1.8)
    ax.add_patch(c2)

    h2 = patches.FancyBboxPatch((c2_x + 10, y_pos + card_h - 48), card_w - 20, 38,
                                boxstyle="round,pad=4,rounding_size=8",
                                facecolor='#0b261b', edgecolor=emerald, linewidth=1.2)
    ax.add_patch(h2)
    ax.text(c2_x + card_w/2, y_pos + card_h - 29, "ZERO-TRUST SCORING", fontsize=11, fontweight='bold',
            color='#69f0ae', ha='center', va='center')

    c2_bullets = [
        ("Dynamic Trust Score", "Continuous 0-100 risk rating evaluated on every active packet flow.", emerald),
        ("5 Micro-Segmentation Zones", "Isolates Loopback, LAN, Trusted Cloud, Public Web, High-Risk.", cyan),
        ("Heuristic Anomaly Flags", "Flags /tmp execution, high-risk ports, missing reverse DNS.", amber),
        ("10s Transient Memory", "Catches microsecond telemetry bursts & ephemeral beacons.", neon_blue),
        ("Immutable Core Whitelist", "Systemd, SSHD & local DNS can never be killed or blocked.", text_sub),
    ]

    for idx, (title, desc, clr) in enumerate(c2_bullets):
        by = y_pos + card_h - 90 - (idx * 84)
        b_box = patches.FancyBboxPatch((c2_x + 12, by - 24), card_w - 24, 62,
                                       boxstyle="round,pad=3,rounding_size=6",
                                       facecolor=card_inner, edgecolor=card_border, linewidth=1)
        ax.add_patch(b_box)
        ax.text(c2_x + 22, by + 18, f">> {title}", fontsize=9.5, fontweight='bold', color=clr)
        ax.text(c2_x + 22, by - 6, desc, fontsize=8, color=text_sub, wrap=True)

    # Card 3: Google Gemini AI Copilot
    c3_x = start_x + 2 * spacing
    c3 = patches.FancyBboxPatch((c3_x, y_pos), card_w, card_h, boxstyle="round,pad=8,rounding_size=12",
                                facecolor=card_bg, edgecolor=purple, linewidth=1.8)
    ax.add_patch(c3)

    h3 = patches.FancyBboxPatch((c3_x + 10, y_pos + card_h - 48), card_w - 20, 38,
                                boxstyle="round,pad=4,rounding_size=8",
                                facecolor='#270f38', edgecolor=purple, linewidth=1.2)
    ax.add_patch(h3)
    ax.text(c3_x + card_w/2, y_pos + card_h - 29, "GOOGLE GEMINI AI", fontsize=11, fontweight='bold',
            color='#ea80fc', ha='center', va='center')

    c3_bullets = [
        ("Plain-English Explain [E]", "Translates complex hex telemetry into clear 2-sentence safety summaries.", purple),
        ("Interactive Copilot [A]", "Natural language Q&A: 'Is my system safe?', 'Why is Chrome uploading?'.", cyan),
        ("Antigravity SDK Bridge", "Native integration with google.antigravity Agent workflow.", neon_blue),
        ("Google Account / API Key", "Seamlessly supports GEMINI_API_KEY, config.json & OAuth.", emerald),
        ("Offline Fallback Mode", "Zero downtime: switches automatically to local heuristics.", text_sub),
    ]

    for idx, (title, desc, clr) in enumerate(c3_bullets):
        by = y_pos + card_h - 90 - (idx * 84)
        b_box = patches.FancyBboxPatch((c3_x + 12, by - 24), card_w - 24, 62,
                                       boxstyle="round,pad=3,rounding_size=6",
                                       facecolor=card_inner, edgecolor=card_border, linewidth=1)
        ax.add_patch(b_box)
        ax.text(c3_x + 22, by + 18, f">> {title}", fontsize=9.5, fontweight='bold', color=clr)
        ax.text(c3_x + 22, by - 6, desc, fontsize=8, color=text_sub, wrap=True)

    # Card 4: Modern Modular Textual TUI & Netfilter
    c4_x = start_x + 3 * spacing
    c4 = patches.FancyBboxPatch((c4_x, y_pos), card_w, card_h, boxstyle="round,pad=8,rounding_size=12",
                                facecolor=card_bg, edgecolor=cyan, linewidth=1.8)
    ax.add_patch(c4)

    h4 = patches.FancyBboxPatch((c4_x + 10, y_pos + card_h - 48), card_w - 20, 38,
                                boxstyle="round,pad=4,rounding_size=8",
                                facecolor='#0b2633', edgecolor=cyan, linewidth=1.2)
    ax.add_patch(h4)
    ax.text(c4_x + card_w/2, y_pos + card_h - 29, "TEXTUAL TUI & NETFILTER", fontsize=11, fontweight='bold',
            color='#80d8ff', ha='center', va='center')

    c4_bullets = [
        ("Zero-Rolling Viewport", "Textual alternate screen DataTable eliminates terminal rolling jitter.", cyan),
        ("Kernel Netfilter Dropping", "One-touch [B] key injects kernel iptables INPUT/OUTPUT drop rules.", coral),
        ("Deep Process Inspector", "Traverses /proc to display PID, exe, full cmdline & user UID.", amber),
        ("Live Multi-Field Search", "Press [/] to filter live flows by process, port, host or IP instantly.", emerald),
        ("Crafted in California", "100% open source Apache 2.0. Clean, decoupled, modular architecture.", text_sub),
    ]

    for idx, (title, desc, clr) in enumerate(c4_bullets):
        by = y_pos + card_h - 90 - (idx * 84)
        b_box = patches.FancyBboxPatch((c4_x + 12, by - 24), card_w - 24, 62,
                                       boxstyle="round,pad=3,rounding_size=6",
                                       facecolor=card_inner, edgecolor=card_border, linewidth=1)
        ax.add_patch(b_box)
        ax.text(c4_x + 22, by + 18, f">> {title}", fontsize=9.5, fontweight='bold', color=clr)
        ax.text(c4_x + 22, by - 6, desc, fontsize=8, color=text_sub, wrap=True)

    # --- BOTTOM QUICK-LAUNCH & BADGE FOOTER ---
    footer_box = patches.FancyBboxPatch((75, 45), 1450, 125, boxstyle="round,pad=8,rounding_size=10",
                                        facecolor='#0a1122', edgecolor=card_border, linewidth=1.5)
    ax.add_patch(footer_box)

    ax.text(105, 138, "QUICK START (CLONE & RUN IN 10 SECONDS):", fontsize=11, fontweight='bold', color=amber)

    cmd_box = patches.FancyBboxPatch((100, 72), 920, 48, boxstyle="round,pad=4,rounding_size=6",
                                     facecolor='#040711', edgecolor=cyan, linewidth=1.2)
    ax.add_patch(cmd_box)
    ax.text(120, 96, "git clone https://github.com/dparksports/gort-firewall.git && cd gort-firewall && sudo ./run.sh",
            fontsize=10.5, fontfamily='monospace', fontweight='bold', color='#a7ffeb')

    # Badges on bottom right
    badges = [
        ("100% Open Source", emerald),
        ("Apache 2.0", cyan),
        ("Python 3.10+", neon_blue),
        ("Made with ❤️ in California", coral)
    ]
    for i, (b_text, b_color) in enumerate(badges):
        bx = 1060 + (i % 2) * 230
        by = 120 if i < 2 else 76
        b_rect = patches.FancyBboxPatch((bx, by), 215, 34, boxstyle="round,pad=3,rounding_size=6",
                                        facecolor='#141f38', edgecolor=b_color, linewidth=1.2)
        ax.add_patch(b_rect)
        ax.text(bx + 107, by + 17, b_text, fontsize=9.5, fontweight='bold', color=text_white, ha='center', va='center')

    plt.tight_layout()
    plt.savefig('linkedin_infographic.png', dpi=150, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("Generated linkedin_infographic.png successfully!")

if __name__ == '__main__':
    draw_linkedin_infographic()
