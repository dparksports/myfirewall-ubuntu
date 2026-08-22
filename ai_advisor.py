"""
AI Security Advisor for Gort Firewall powered by Google Antigravity & Gemini.
Provides real-time plain English connection explanations, Zero-Trust threat triage,
and interactive security copilot Q&A with offline heuristic fallback.
"""

import asyncio
from typing import Dict, Any, List
import zero_trust_engine as zte

# Try importing Antigravity SDK
HAS_ANTIGRAVITY_SDK = False
try:
    from google.antigravity import Agent, LocalAgentConfig, CapabilitiesConfig
    HAS_ANTIGRAVITY_SDK = True
except ImportError:
    HAS_ANTIGRAVITY_SDK = False


class GortAIAdvisor:
    """Intelligent Security Advisor embedded in Gort Firewall."""

    def __init__(self):
        self.sdk_available = HAS_ANTIGRAVITY_SDK

    def is_ai_ready(self) -> bool:
        return self.sdk_available

    async def explain_connection(self, conn: Dict[str, Any]) -> str:
        """Generates a plain-English explanation for a network connection."""
        zt_eval = zte.evaluate_zero_trust(conn)
        name = conn.get("name") or "unknown"
        exe = conn.get("exe") or "unknown binary"
        remote_ip = conn.get("remote_ip") or "0.0.0.0"
        remote_port = conn.get("remote_port") or 0
        hostname = conn.get("hostname") or "unresolved"
        geo = conn.get("geo") or "Unknown Region"
        direction = conn.get("direction") or "OUTBOUND"
        score = zt_eval["score"]
        anomalies = zt_eval["anomalies"]
        zone_desc = zt_eval["zone_desc"]

        if self.sdk_available:
            try:
                config = LocalAgentConfig(
                    system_instructions=(
                        "You are Gort, an autonomous Linux security advisor. "
                        "Explain network connections to non-technical users in 2 concise sentences: "
                        "1) What the application is doing and who it is communicating with. "
                        "2) A clear safety assessment and recommendation (Safe, Monitor, or Block)."
                    ),
                    capabilities=CapabilitiesConfig()
                )
                async with Agent(config) as agent:
                    prompt = (
                        f"Evaluate this flow: App '{name}' ({exe}) connecting {direction} to "
                        f"{remote_ip}:{remote_port} ({hostname}, {geo}). "
                        f"Zero-Trust Zone: {zone_desc}, Trust Score: {score}/100, "
                        f"Heuristic Flags: {', '.join(anomalies) if anomalies else 'None'}."
                    )
                    resp = await agent.chat(prompt)
                    return resp.text.strip()
            except Exception as e:
                # Fallback to local heuristic engine on network/token error
                pass

        # Offline / Heuristic Explanation Engine
        return self._heuristic_explanation(conn, zt_eval)

    def _heuristic_explanation(self, conn: Dict[str, Any], zt: Dict[str, Any]) -> str:
        name = conn.get("name") or "Application"
        remote_ip = conn.get("remote_ip") or ""
        hostname = conn.get("hostname") or ""
        geo = conn.get("geo") or "Remote Server"
        port = conn.get("remote_port")
        score = zt["score"]
        anomalies = zt["anomalies"]
        zone = zt["zone"]

        dest = hostname if (hostname and hostname != remote_ip) else f"{remote_ip} ({geo})"

        if score >= 80:
            return (
                f"🛡️ [bold green]Normal & Trusted Traffic[/]: '{name}' is communicating with {dest} on port {port}. "
                f"This flow matches standard verified services in {zt['zone_desc']}. No action required."
            )
        elif score >= 50:
            anom_str = f" (Flagged: {', '.join(anomalies)})" if anomalies else ""
            return (
                f"⚠️ [bold yellow]Unverified Activity[/]: '{name}' is transmitting data to {dest}{anom_str}. "
                f"While not necessarily malicious, this destination is unverified. Recommend monitoring."
            )
        else:
            anom_str = f" Anomalies detected: {', '.join(anomalies)}." if anomalies else ""
            return (
                f"🚨 [bold red]High-Risk Alert[/]: Suspicious traffic detected from '{name}' targeting {dest} on port {port}.{anom_str} "
                f"Recommendation: Neutralize immediately by pressing [bold red][B][/] to block."
            )

    async def ask_copilot(self, user_question: str, active_conns: List[Dict[str, Any]]) -> str:
        """Answers general user questions or provides custom incident triage."""
        if not user_question.strip():
            return "Please type a question for Gort AI Copilot."

        if self.sdk_available:
            try:
                conns_summary = "\n".join([
                    f"- {c.get('name')} (PID {c.get('pid')}): {c.get('remote_ip')}:{c.get('remote_port')} ({c.get('geo', 'Unknown')})"
                    for c in active_conns[:15]
                ])
                config = LocalAgentConfig(
                    system_instructions=(
                        "You are Gort AI, an expert Linux cybersecurity copilot. "
                        "Answer user questions clearly and concisely. "
                        "Explain firewall concepts in simple terms and give actionable advice."
                    ),
                    capabilities=CapabilitiesConfig()
                )
                async with Agent(config) as agent:
                    prompt = (
                        f"Active connections on user machine:\n{conns_summary}\n\n"
                        f"User question: {user_question}"
                    )
                    resp = await agent.chat(prompt)
                    return resp.text.strip()
            except Exception as e:
                pass

        # Offline Copilot Fallback
        q_lower = user_question.lower()
        if "block" in q_lower or "drop" in q_lower:
            return "To block an IP, highlight the connection row and press 'B'. Gort will inject an iptables drop rule in the Linux kernel."
        elif "ignore" in q_lower or "hide" in q_lower:
            return "To hide trusted applications like Chrome or Spotify, highlight the row and press 'I'. You can also ignore entire subnet CIDRs."
        elif "safe" in q_lower or "score" in q_lower:
            return "Gort evaluates every connection with a Zero-Trust score (0-100). Green (80+) is trusted, Yellow (50-79) requires verification, and Red (<50) indicates high risk."
        else:
            return (
                f"Gort AI Copilot is currently monitoring {len(active_conns)} active flows. "
                "Highlight any row and press 'E' for an in-depth safety breakdown or 'B' to block."
            )


# Global Singleton
advisor = GortAIAdvisor()
