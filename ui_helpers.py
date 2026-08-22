"""
UI presentation and string formatting helpers for Gort Firewall.
"""

import time
from typing import Optional


def fmt_duration(first_seen: float) -> str:
    """Formats seconds elapsed since first_seen into a compact string."""
    secs = int(time.time() - first_seen)
    if secs < 0:
        secs = 0
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    h = secs // 3600
    m = (secs % 3600) // 60
    return f"{h}h{m:02d}m"


def fmt_pkts(n: Optional[int]) -> str:
    """Formats a packet count compactly (None → '—')."""
    if n is None:
        return "—"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def fmt_bytes_rate(rate: Optional[float]) -> str:
    """Formats byte/sec rate into KB/s or MB/s."""
    if rate is None or rate < 0:
        rate = 0.0
    if rate >= 1_048_576:
        return f"{rate / 1_048_576:.2f} MB/s"
    if rate >= 1024:
        return f"{rate / 1024:.1f} KB/s"
    return f"{rate:.0f} B/s"
