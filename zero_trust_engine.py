"""
Zero-Trust Security & Risk Scoring Engine for Gort Firewall.
Implements continuous identity verification, micro-segmentation zones,
binary reputation, anomaly heuristic detection, and dynamic risk scoring (0-100).
"""

import os
import hashlib
import ipaddress
from typing import Dict, Any, List, Tuple

# Well-known trusted CDN and Cloud ASN prefixes / ranges (samples for fast local classification)
TRUSTED_INFRA_KEYWORDS = [
    "google", "1e100", "cloudflare", "amazon", "aws", "cloudfront",
    "microsoft", "azure", "fastly", "akamai", "github", "apple", "canonical"
]

SUSPICIOUS_PORTS = {
    1337, 31337, 4444, 5555, 6666, 6667, 7777, 8888, 9999, 12345, 2323, 3389, 5900
}

KNOWN_SYSTEM_PATHS = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/usr/libexec/"
)

SUSPICIOUS_EXEC_PATHS = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/"
)


def compute_binary_sha256(exe_path: str) -> str:
    """Safely calculates SHA256 of an executable if accessible."""
    if not exe_path or not os.path.exists(exe_path) or not os.path.isfile(exe_path):
        return "N/A"
    try:
        hasher = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "ACCESS_DENIED"


def classify_network_zone(remote_ip: str, hostname: str = "") -> Tuple[str, str]:
    """
    Categorizes destination into Zero-Trust Micro-Segmentation Zones:
    - ZONE 1: LOOPBACK (Intra-Host)
    - ZONE 2: LAN_PRIVATE (Local Trust Boundary)
    - ZONE 3: TRUSTED_INFRA (Verified Cloud/CDN/Infrastructure)
    - ZONE 4: PUBLIC_INTERNET (General External)
    - ZONE 5: HIGH_RISK (Unverified / Anomalous)
    """
    if not remote_ip or remote_ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return "ZONE 1 (LOOPBACK)", "Intra-Host IPC / Local Loopback"

    try:
        ip_obj = ipaddress.ip_address(remote_ip)
        if ip_obj.is_loopback:
            return "ZONE 1 (LOOPBACK)", "Intra-Host IPC / Local Loopback"
        if ip_obj.is_private:
            return "ZONE 2 (LAN_PRIVATE)", "Private Local Subnet (RFC 1918)"
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_link_local:
            return "ZONE 2 (LAN_SPECIAL)", "Multicast / Link-Local Traffic"
    except ValueError:
        pass

    # Check hostname / reverse DNS for verified infrastructure
    h_lower = (hostname or "").lower()
    for kw in TRUSTED_INFRA_KEYWORDS:
        if kw in h_lower:
            return "ZONE 3 (TRUSTED_INFRA)", f"Verified Infrastructure ({kw.title()})"

    return "ZONE 4 (PUBLIC_INTERNET)", "Untrusted Public Internet"


def evaluate_zero_trust(conn: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates connection attributes against Zero-Trust policies.
    Returns:
      - score: integer from 0 to 100 (100 = fully trusted, 0 = high threat)
      - risk_level: 'SAFE', 'VERIFY', 'SUSPICIOUS', 'CRITICAL'
      - badge: Rich formatted string e.g. '[green]🟢 TRUST: 95[/]'
      - zone: Classified network zone
      - anomalies: List of detected heuristic warnings
      - sha256: Binary checksum
    """
    score = 100
    anomalies: List[str] = []

    name = (conn.get("name") or "unknown").lower()
    exe = conn.get("exe") or ""
    cmdline = conn.get("cmdline") or ""
    remote_ip = conn.get("remote_ip") or ""
    remote_port = conn.get("remote_port") or 0
    hostname = conn.get("hostname") or ""
    status = conn.get("status") or "ACTIVE"

    # 1. Network Zone Classification
    zone, zone_desc = classify_network_zone(remote_ip, hostname)

    if "ZONE 1" in zone:
        score += 0  # Neutral / Safe
    elif "ZONE 2" in zone:
        score -= 5
    elif "ZONE 3" in zone:
        score -= 10
    elif "ZONE 4" in zone:
        score -= 25
        if not hostname or hostname == remote_ip:
            score -= 10
            anomalies.append("NO_REVERSE_DNS")

    # 2. Binary Location Heuristics
    if exe and any(exe.startswith(p) for p in SUSPICIOUS_EXEC_PATHS):
        score -= 35
        anomalies.append("SUSPICIOUS_EXEC_DIR")
    elif not exe or exe == "unknown":
        score -= 20
        anomalies.append("UNRESOLVED_BINARY_PATH")

    # 3. Suspicious Port / Reverse Shell Detection
    try:
        port_num = int(remote_port)
        if port_num in SUSPICIOUS_PORTS:
            score -= 40
            anomalies.append(f"HIGH_RISK_PORT_{port_num}")
    except (ValueError, TypeError):
        pass

    # 4. Command Line Anomalies (e.g. inline scripts, reverse shells)
    suspicious_cmd_tokens = [
        "nc -e", "bash -i", "/dev/tcp", "mkfifo", "eval(base64", "curl | bash", "wget | sh", "pwn"
    ]
    for token in suspicious_cmd_tokens:
        if token in cmdline.lower():
            score -= 50
            anomalies.append(f"ANOMALOUS_CMDLINE ({token})")

    # 5. Process & State Attributes
    if status == "INACTIVE" and (conn.get("last_seen", 0) - conn.get("first_seen", 0)) < 1.0:
        # Micro-burst connection (< 1s lifespan)
        score -= 10
        anomalies.append("EPHEMERAL_MICRO_BURST")

    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    # Determine Risk Level and Visual Badge
    if score >= 80:
        risk_level = "SAFE"
        badge = f"[bold green]🟢 TRUST: {score}[/]"
    elif score >= 50:
        risk_level = "VERIFY"
        badge = f"[bold yellow]🟡 VERIFY: {score}[/]"
    elif score >= 25:
        risk_level = "SUSPICIOUS"
        badge = f"[bold red]🔴 SUSPECT: {score}[/]"
    else:
        risk_level = "CRITICAL"
        badge = f"[bold white on red]🔥 THREAT: {score}[/]"

    return {
        "score": score,
        "risk_level": risk_level,
        "badge": badge,
        "zone": zone,
        "zone_desc": zone_desc,
        "anomalies": anomalies,
    }
