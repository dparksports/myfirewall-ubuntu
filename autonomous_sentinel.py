"""
Autonomous Intruder Defense System (AIDS) & Bad USB Sentinel for Gort Firewall.
Implements multi-signal threat triangulation, graduated 4-tier response ladder,
non-destructive SIGSTOP freezing, TTL rule decay, and structured forensic logging.
"""

import os
import sys
import time
import signal
import json
import threading
from typing import Dict, Any, List, Optional, Tuple

import myfirewall_core as core
import zero_trust_engine as zte
import firewall_manager

AUTONOMOUS_LOG_FILE = os.path.expanduser("~/.config/myfirewall/autonomous_defense.log")
LOCAL_AUTONOMOUS_LOG = "autonomous_defense.log"

# Protected System Core Binaries & Daemons (Immutable Whitelist - NEVER Autonomous Kill/Block)
IMMUTABLE_SYSTEM_BINARIES = {
    "systemd", "systemd-resolved", "systemd-journald", "systemd-logind",
    "sshd", "chronyd", "ntpd", "dbus-daemon", "cupsd", "dockerd", "containerd",
    "init", "kthreadd"
}

IMMUTABLE_IPS = {
    "127.0.0.1", "::1", "0.0.0.0", "::"
}

# Reverse shell / high-confidence intrusion command signatures
CRITICAL_INTRUDER_PATTERNS = [
    "bash -i", "/dev/tcp/", "nc -e", "nc.traditional -e", "mkfifo",
    "python -c import socket", "python3 -c import socket",
    "perl -e 'use Socket", "php -r '$sock=fsockopen",
    "ruby -rsocket -e", "curl | bash", "wget | sh", "eval(base64_decode"
]


class AutonomousIncident:
    """Represents a recorded autonomous defense action."""

    def __init__(
        self,
        incident_id: str,
        timestamp: float,
        confidence_score: int,
        action_tier: str,
        threat_type: str,
        process_info: Dict[str, Any],
        network_info: Dict[str, Any],
        evidence: List[str],
        actions_taken: List[str],
        ttl_seconds: int = 0
    ):
        self.incident_id = incident_id
        self.timestamp = timestamp
        self.confidence_score = confidence_score
        self.action_tier = action_tier
        self.threat_type = threat_type
        self.process_info = process_info
        self.network_info = network_info
        self.evidence = evidence
        self.actions_taken = actions_taken
        self.ttl_seconds = ttl_seconds
        self.expires_at = (timestamp + ttl_seconds) if ttl_seconds > 0 else 0
        self.rolled_back = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
            "confidence_score": self.confidence_score,
            "action_tier": self.action_tier,
            "threat_type": self.threat_type,
            "process": self.process_info,
            "network": self.network_info,
            "evidence": self.evidence,
            "actions_taken": self.actions_taken,
            "ttl_seconds": self.ttl_seconds,
            "rolled_back": self.rolled_back
        }


class AutonomousSentinel:
    """Core autonomous intrusion detector and proactive response controller."""

    def __init__(self):
        firewall_manager.init_firewall()
        self.enabled = True
        self.active_incidents: List[AutonomousIncident] = []
        self.frozen_pids: Dict[int, Dict[str, Any]] = {}
        self.temporary_drops: Dict[str, float] = {}  # ip -> expire_timestamp
        self._lock = threading.Lock()
        self._decay_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Starts background TTL decay and evaluation workers."""
        if self._running:
            return
        self._running = True
        self._decay_thread = threading.Thread(target=self._ttl_decay_loop, daemon=True, name="GortSentinelTTL")
        self._decay_thread.start()

    def stop(self):
        self._running = False

    def is_immutable(self, proc_name: str, exe: str, ip: str) -> bool:
        """Returns True if the process or IP is protected by the immutable whitelist."""
        p_name = (proc_name or "").lower()
        if p_name in IMMUTABLE_SYSTEM_BINARIES:
            return True
        if exe:
            base_exe = os.path.basename(exe).lower()
            if base_exe in IMMUTABLE_SYSTEM_BINARIES:
                return True
        if ip in IMMUTABLE_IPS or core.is_local_ip(ip):
            return True
        return False

    def evaluate_and_respond(self, conn: Dict[str, Any]) -> Optional[AutonomousIncident]:
        """
        Evaluates a live connection against multi-signal intrusion criteria.
        Triggers graduated proactive response if confidence threshold is met.
        """
        if not self.enabled:
            return None

        proc_name = conn.get("name") or "unknown"
        exe = conn.get("exe") or ""
        pid = conn.get("pid")
        cmdline = conn.get("cmdline") or ""
        remote_ip = conn.get("remote_ip") or ""
        remote_port = conn.get("remote_port") or 0
        user = conn.get("username") or conn.get("user") or "unknown"

        # 1. Check Immutable Core Whitelist
        if self.is_immutable(proc_name, exe, remote_ip):
            return None

        # 2. Multi-Signal Evidence Triangulation
        zt_eval = zte.evaluate_zero_trust(conn)
        trust_score = zt_eval["score"]
        evidence: List[str] = list(zt_eval["anomalies"])
        threat_type = "ANOMALOUS_CONNECTION"
        confidence = 100 - trust_score  # Invert to threat confidence (0-100)

        # Check for critical reverse shell / intruder command line patterns (Tier 3)
        cmd_lower = cmdline.lower()
        has_critical_sig = False
        for pattern in CRITICAL_INTRUDER_PATTERNS:
            if pattern in cmd_lower:
                confidence = 98
                evidence.append(f"CRITICAL_SIGNATURE ({pattern})")
                threat_type = "REVERSE_SHELL_INTRUDER"
                has_critical_sig = True
                break

        # Check for unverified execution path without critical signature (Tier 2: Freeze & Pause)
        if not has_critical_sig and "SUSPICIOUS_EXEC_DIR" in zt_eval["anomalies"]:
            confidence = min(92, max(confidence, 85))
            threat_type = "UNTRUSTED_EXEC_PATH_DROPPER"

        # Check for Bad USB / PoisonTap Interface indicators
        if conn.get("interface", "").startswith(("usb", "rndis")):
            evidence.append("USB_ATTACHED_INTERFACE")
            confidence = min(92, max(confidence, 85))
            threat_type = "BAD_USB_POISONTAP_HIJACK"

        # Don't act if threat confidence is below Tier 1 (< 60)
        if confidence < 60:
            return None

        # 3. Determine Graduated Action Tier
        incident_id = f"INC-{int(time.time())}-{pid or '0'}"
        actions_taken: List[str] = []
        action_tier = "TIER_0_OBSERVE"
        ttl = 0

        if confidence >= 95:
            # Tier 3: Autonomous Neutralization (SIGKILL + Netfilter Drop)
            action_tier = "TIER_3_NEUTRALIZE"
            if pid and pid > 1 and not core.is_mock_mode():
                try:
                    os.kill(pid, signal.SIGKILL)
                    actions_taken.append(f"PROCESS_TERMINATED (SIGKILL PID {pid})")
                except ProcessLookupError:
                    pass
                except PermissionError:
                    actions_taken.append(f"TERMINATE_FAILED_PERMISSION (PID {pid})")
            elif core.is_mock_mode():
                actions_taken.append(f"MOCK_PROCESS_TERMINATED (SIGKILL PID {pid})")

            # Permanent Netfilter Drop
            if remote_ip and remote_ip not in core.blocked_ips:
                core.toggle_ip_block(remote_ip)
                actions_taken.append(f"NETFILTER_PERMANENT_DROP ({remote_ip})")

        elif confidence >= 80:
            # Tier 2: Non-Destructive Freeze (SIGSTOP) + 15m Temp Drop
            action_tier = "TIER_2_FREEZE_PAUSE"
            ttl = 900  # 15 minutes
            if pid and pid > 1 and not core.is_mock_mode():
                try:
                    os.kill(pid, signal.SIGSTOP)
                    actions_taken.append(f"PROCESS_FROZEN (SIGSTOP PID {pid})")
                    with self._lock:
                        self.frozen_pids[pid] = {
                            "incident_id": incident_id,
                            "proc_name": proc_name,
                            "exe": exe,
                            "remote_ip": remote_ip,
                            "frozen_at": time.time()
                        }
                except ProcessLookupError:
                    pass
                except PermissionError:
                    actions_taken.append(f"FREEZE_FAILED_PERMISSION (PID {pid})")
            elif core.is_mock_mode():
                actions_taken.append(f"MOCK_PROCESS_FROZEN (SIGSTOP PID {pid})")
                with self._lock:
                    self.frozen_pids[pid] = {
                        "incident_id": incident_id,
                        "proc_name": proc_name,
                        "exe": exe,
                        "remote_ip": remote_ip,
                        "frozen_at": time.time()
                    }

            # Temporary Netfilter Drop
            if remote_ip and remote_ip not in core.blocked_ips:
                core.toggle_ip_block(remote_ip)
                actions_taken.append(f"NETFILTER_TEMP_DROP_{ttl}S ({remote_ip})")
                with self._lock:
                    self.temporary_drops[remote_ip] = time.time() + ttl

        else:
            # Tier 1: Soft Alert & Micro-Throttle
            action_tier = "TIER_1_THROTTLE_ALERT"
            actions_taken.append(f"SECURITY_ALERT_LOGGED ({remote_ip})")

        incident = AutonomousIncident(
            incident_id=incident_id,
            timestamp=time.time(),
            confidence_score=confidence,
            action_tier=action_tier,
            threat_type=threat_type,
            process_info={"name": proc_name, "pid": pid, "exe": exe, "cmdline": cmdline, "user": user},
            network_info={"remote_ip": remote_ip, "remote_port": remote_port, "protocol": conn.get("protocol", "TCP")},
            evidence=evidence,
            actions_taken=actions_taken,
            ttl_seconds=ttl
        )

        with self._lock:
            self.active_incidents.append(incident)
            # Keep max 100 recent incidents in memory
            if len(self.active_incidents) > 100:
                self.active_incidents.pop(0)

        self._write_incident_log(incident)
        return incident

    def rollback_incident(self, incident_id: str) -> bool:
        """
        1-Click Reversal: Unfreezes process (SIGCONT) and lifts temporary Netfilter drop.
        """
        with self._lock:
            target_inc = next((inc for inc in self.active_incidents if inc.incident_id == incident_id), None)
            if not target_inc:
                return False

            target_inc.rolled_back = True
            pid = target_inc.process_info.get("pid")
            remote_ip = target_inc.network_info.get("remote_ip")

            # 1. Unfreeze process if frozen
            if pid and pid in self.frozen_pids:
                if not core.is_mock_mode():
                    try:
                        os.kill(pid, signal.SIGCONT)
                    except (ProcessLookupError, PermissionError):
                        pass
                del self.frozen_pids[pid]

            # 2. Lift Netfilter Block
            if remote_ip and remote_ip in core.blocked_ips:
                core.toggle_ip_block(remote_ip)
            if remote_ip in self.temporary_drops:
                del self.temporary_drops[remote_ip]

            # 3. Add to user ignore policy to prevent immediate re-trigger
            if remote_ip:
                core.toggle_ip_ignore(remote_ip)

            return True

    def _ttl_decay_loop(self):
        """Background worker that gracefully decays expired temporary Netfilter rules."""
        while self._running:
            now = time.time()
            with self._lock:
                expired_ips = [ip for ip, exp in self.temporary_drops.items() if now >= exp]
                for ip in expired_ips:
                    if ip in core.blocked_ips:
                        core.toggle_ip_block(ip)
                    del self.temporary_drops[ip]

            time.sleep(1.0)

    def _write_incident_log(self, incident: AutonomousIncident):
        """Appends incident record to JSON-lines audit trail."""
        try:
            line = json.dumps(incident.to_dict()) + "\n"
            os.makedirs(os.path.dirname(AUTONOMOUS_LOG_FILE), exist_ok=True)
            with open(AUTONOMOUS_LOG_FILE, "a") as f:
                f.write(line)
            with open(LOCAL_AUTONOMOUS_LOG, "a") as f:
                f.write(line)
        except Exception:
            pass


# Global Singleton Instance
sentinel = AutonomousSentinel()
