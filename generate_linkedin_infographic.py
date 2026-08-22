#!/usr/bin/env python3
"""
Generate a simplified, high-impact corporate LinkedIn Infographic for Gort Firewall.
Centered on the core theme:
"Don't be suspicious, just run this. You never know what's lurking on your Ubuntu workstation or laptop."
Outputs: linkedin_infographic.png (1920x1080, 16:9 4K presentation asset)
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches

def draw_simplified_infographic():
    fig, ax = plt.subplots(figsize=(16, 9), dpi=150)
    fig.patch.set_facecolor('#080c18')  # Deep obsidian
    ax.set_facecolor('#080c18')
    ax.set_xlim(0, 1600)
    ax.set_ylim(0, 900)
    ax.axis('off')

    # Color Palette
    cyan = '#00f0ff'
    emerald = '#00e676'
    coral = '#ff3d57'
    purple = '#c084fc'
    amber = '#ffb300'
    text_white = '#ffffff'
    text_sub = '#cbd5e1'
    card_bg = '#0f172a'
    card_border = '#1e293b'

    # Top Brand Bar
    ax.plot([150, 1450], [865, 865], color=cyan, linewidth=2, alpha=0.9)

    # Main Headline (User's One-Liner in Large Bold Typography)
    ax.text(800, 815, "Don't be suspicious, just run this.", fontsize=32, fontweight='bold',
            color=text_white, ha='center', va='center', fontfamily='sans-serif')
    ax.text(800, 765, "You never know what's lurking on your Ubuntu workstation or laptop.",
            fontsize=18, fontweight='bold', color=cyan, ha='center', va='center')

    # Sub-tagline
    ax.text(800, 715, "GORT — Open-Source Linux Terminal Firewall, Zero-Trust Sentinel & Google Gemini AI",
            fontsize=13, color=text_sub, ha='center', va='center')

    # --- 3 SIMPLE, CLEAN CARDS ---
    card_w = 420
    card_h = 420
    y_pos = 220
    spacing = 460
    start_x = 110

    # Card 1: What's Lurking?
    c1_x = start_x + 0 * spacing
    c1 = patches.FancyBboxPatch((c1_x, y_pos), card_w, card_h, boxstyle="round,pad=10,rounding_size=14",
                                facecolor=card_bg, edgecolor=coral, linewidth=2)
    ax.add_patch(c1)

    h1 = patches.FancyBboxPatch((c1_x + 15, y_pos + card_h - 60), card_w - 30, 46,
                                boxstyle="round,pad=5,rounding_size=8",
                                facecolor='#2c111e', edgecolor=coral, linewidth=1.5)
    ax.add_patch(h1)
    ax.text(c1_x + card_w/2, y_pos + card_h - 37, "1. SEE WHAT'S LURKING", fontsize=13, fontweight='bold',
            color='#ff5252', ha='center', va='center')

    bullets_1 = [
        ("Transient Telemetry", "Catches beacons & sockets that close in milliseconds.", coral),
        ("Reverse Shell Shield", "Auto-flags bash /dev/tcp, netcat & dropper scripts.", amber),
        ("Bad USB Protection", "Neutralizes Rubber Ducky & PoisonTap hardware injects.", text_white),
        ("Non-Destructive Freeze", "SIGSTOP pauses intruder in RAM with 1-click rollback [U].", emerald),
    ]
    for idx, (title, desc, clr) in enumerate(bullets_1):
        by = y_pos + card_h - 105 - (idx * 72)
        ax.text(c1_x + 25, by + 12, f">>  {title}", fontsize=11, fontweight='bold', color=clr)
        ax.text(c1_x + 25, by - 12, desc, fontsize=9.5, color=text_sub)

    # Card 2: Zero-Trust Continuous Verification
    c2_x = start_x + 1 * spacing
    c2 = patches.FancyBboxPatch((c2_x, y_pos), card_w, card_h, boxstyle="round,pad=10,rounding_size=14",
                                facecolor=card_bg, edgecolor=emerald, linewidth=2)
    ax.add_patch(c2)

    h2 = patches.FancyBboxPatch((c2_x + 15, y_pos + card_h - 60), card_w - 30, 46,
                                boxstyle="round,pad=5,rounding_size=8",
                                facecolor='#0b2c1e', edgecolor=emerald, linewidth=1.5)
    ax.add_patch(h2)
    ax.text(c2_x + card_w/2, y_pos + card_h - 37, "2. ZERO-TRUST SCORING", fontsize=13, fontweight='bold',
            color='#69f0ae', ha='center', va='center')

    bullets_2 = [
        ("Trust Score (0–100)", "Live security grade calculated for every active connection.", emerald),
        ("5 Network Zones", "Micro-segments Loopback, LAN, Trusted Cloud & High-Risk.", cyan),
        ("Process Provenance", "Maps sockets to PID, executable path, cmdline & user.", text_white),
        ("Zero False Positives", "Core whitelist protects systemd, SSHD & local DNS.", text_sub),
    ]
    for idx, (title, desc, clr) in enumerate(bullets_2):
        by = y_pos + card_h - 105 - (idx * 72)
        ax.text(c2_x + 25, by + 12, f">>  {title}", fontsize=11, fontweight='bold', color=clr)
        ax.text(c2_x + 25, by - 12, desc, fontsize=9.5, color=text_sub)

    # Card 3: Google Gemini AI Copilot
    c3_x = start_x + 2 * spacing
    c3 = patches.FancyBboxPatch((c3_x, y_pos), card_w, card_h, boxstyle="round,pad=10,rounding_size=14",
                                facecolor=card_bg, edgecolor=purple, linewidth=2)
    ax.add_patch(c3)

    h3 = patches.FancyBboxPatch((c3_x + 15, y_pos + card_h - 60), card_w - 30, 46,
                                boxstyle="round,pad=5,rounding_size=8",
                                facecolor='#27103d', edgecolor=purple, linewidth=1.5)
    ax.add_patch(h3)
    ax.text(c3_x + card_w/2, y_pos + card_h - 37, "3. GOOGLE GEMINI AI", fontsize=13, fontweight='bold',
            color='#e879f9', ha='center', va='center')

    bullets_3 = [
        ("Plain-English [E]", "Translates complex hex telemetry into 2-sentence summaries.", purple),
        ("Ask Copilot [A]", "Chat with AI: 'Is this safe?', 'Why is this app connecting?'.", cyan),
        ("Google Account Ready", "Supports Antigravity SDK, GEMINI_API_KEY & OAuth.", text_white),
        ("Offline Fallback", "Always works offline with local heuristic engine.", emerald),
    ]
    for idx, (title, desc, clr) in enumerate(bullets_3):
        by = y_pos + card_h - 105 - (idx * 72)
        ax.text(c3_x + 25, by + 12, f">>  {title}", fontsize=11, fontweight='bold', color=clr)
        ax.text(c3_x + 25, by - 12, desc, fontsize=9.5, color=text_sub)

    # --- BOTTOM CLEAN COMMAND BAR ---
    bot_box = patches.FancyBboxPatch((110, 55), 1380, 125, boxstyle="round,pad=8,rounding_size=12",
                                     facecolor='#0b1329', edgecolor=card_border, linewidth=1.5)
    ax.add_patch(bot_box)

    ax.text(140, 145, "RUN IN 10 SECONDS ON ANY LINUX MACHINE:", fontsize=12, fontweight='bold', color=amber)

    cmd_box = patches.FancyBboxPatch((135, 78), 900, 48, boxstyle="round,pad=4,rounding_size=6",
                                     facecolor='#030712', edgecolor=cyan, linewidth=1.2)
    ax.add_patch(cmd_box)
    ax.text(155, 102, "git clone https://github.com/dparksports/gort-firewall.git && cd gort-firewall && sudo ./run.sh",
            fontsize=10.5, fontfamily='monospace', fontweight='bold', color='#a7ffeb')

    # Badges
    badges = [
        ("100% Open Source", emerald),
        ("Made with ❤️ in California", coral)
    ]
    for i, (b_text, b_color) in enumerate(badges):
        bx = 1065
        by = 108 if i == 0 else 74
        b_rect = patches.FancyBboxPatch((bx, by), 390, 30, boxstyle="round,pad=3,rounding_size=6",
                                        facecolor='#16223d', edgecolor=b_color, linewidth=1.2)
        ax.add_patch(b_rect)
        ax.text(bx + 195, by + 15, b_text, fontsize=10, fontweight='bold', color=text_white, ha='center', va='center')

    plt.tight_layout()
    plt.savefig('linkedin_infographic.png', dpi=150, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close()
    print("Generated simplified linkedin_infographic.png successfully!")

if __name__ == '__main__':
    draw_simplified_infographic()
