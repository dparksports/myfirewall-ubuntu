"""
AI Security Advisor for Gort Firewall powered by Google Antigravity & Gemini.
Provides real-time plain English connection explanations, Zero-Trust threat triage,
and interactive security copilot Q&A with offline heuristic fallback.
"""

import os
import json
import asyncio
import requests
from typing import Dict, Any, List, Optional
import zero_trust_engine as zte

CONFIG_FILE = os.path.expanduser("~/.config/myfirewall/config.json")

# Try importing Antigravity SDK
HAS_ANTIGRAVITY_SDK = False
try:
    from google.antigravity import Agent, LocalAgentConfig, CapabilitiesConfig
    HAS_ANTIGRAVITY_SDK = True
except ImportError:
    HAS_ANTIGRAVITY_SDK = False


def get_gemini_api_key() -> Optional[str]:
    """Retrieves the Gemini API Key from environment or local configuration file."""
    # 1. Check environment variables
    env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if env_key:
        return env_key.strip()

    # 2. Check ~/.config/myfirewall/config.json
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                key = data.get("gemini_api_key") or data.get("google_api_key")
                if key:
                    return key.strip()
        except Exception:
            pass

    return None


def call_gemini_rest_api(api_key: str, prompt: str, system_instruction: str = "") -> Optional[str]:
    """Directly queries the Google Gemini REST API using dynamic model resolution."""
    import auth_manager as am
    model = am.auth_manager.get_active_model()
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload: Dict[str, Any] = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }
    if system_instruction:
        payload["systemInstruction"] = {
            "parts": [{"text": system_instruction}]
        }

    try:
        resp = requests.post(endpoint, json=payload, timeout=6.0)
        if resp.status_code == 200:
            res_json = resp.json()
            candidates = res_json.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "").strip()
        elif resp.status_code in (404, 400):
            # Model may have changed; dynamically re-discover best model
            best_model, _, _ = am.auth_manager.discover_and_verify_best_model(api_key)
            if best_model and best_model != model:
                am.auth_manager.save_api_key(api_key, active_model=best_model)
                retry_endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{best_model}:generateContent?key={api_key}"
                retry_resp = requests.post(retry_endpoint, json=payload, timeout=6.0)
                if retry_resp.status_code == 200:
                    candidates = retry_resp.json().get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()
    except Exception:
        pass
    return None


class GortAIAdvisor:
    """Intelligent Security Advisor embedded in Gort Firewall."""

    def __init__(self):
        self.sdk_available = HAS_ANTIGRAVITY_SDK

    def is_ai_ready(self) -> bool:
        return self.sdk_available or bool(get_gemini_api_key())

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

        system_prompt = (
            "You are Gort, an autonomous Linux security advisor. "
            "Explain network connections to non-technical users in 2 concise sentences: "
            "1) What the application is doing and who it is communicating with. "
            "2) A clear safety assessment and recommendation (Safe, Monitor, or Block)."
        )
        user_prompt = (
            f"Evaluate this flow: App '{name}' ({exe}) connecting {direction} to "
            f"{remote_ip}:{remote_port} ({hostname}, {geo}). "
            f"Zero-Trust Zone: {zone_desc}, Trust Score: {score}/100, "
            f"Heuristic Flags: {', '.join(anomalies) if anomalies else 'None'}."
        )

        # 1. Try Antigravity SDK
        if self.sdk_available:
            try:
                config = LocalAgentConfig(
                    system_instructions=system_prompt,
                    capabilities=CapabilitiesConfig()
                )
                async with Agent(config) as agent:
                    resp = await agent.chat(user_prompt)
                    return resp.text.strip()
            except Exception:
                pass

        # 2. Try Gemini API Key (Direct)
        api_key = get_gemini_api_key()
        if api_key:
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, call_gemini_rest_api, api_key, user_prompt, system_prompt)
            if res:
                return res

        # 3. Offline / Heuristic Explanation Engine Fallback
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

        conns_summary = "\n".join([
            f"- {c.get('name')} (PID {c.get('pid')}): {c.get('remote_ip')}:{c.get('remote_port')} ({c.get('geo', 'Unknown')})"
            for c in active_conns[:15]
        ])
        system_prompt = (
            "You are Gort AI, an expert Linux cybersecurity copilot. "
            "Answer user questions clearly and concisely. "
            "Explain firewall concepts in simple terms and give actionable advice."
        )
        user_prompt = (
            f"Active connections on user machine:\n{conns_summary}\n\n"
            f"User question: {user_question}"
        )

        # 1. Try Antigravity SDK
        if self.sdk_available:
            try:
                config = LocalAgentConfig(
                    system_instructions=system_prompt,
                    capabilities=CapabilitiesConfig()
                )
                async with Agent(config) as agent:
                    resp = await agent.chat(user_prompt)
                    return resp.text.strip()
            except Exception:
                pass

        # 2. Try Gemini API Key (Direct)
        api_key = get_gemini_api_key()
        if api_key:
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, call_gemini_rest_api, api_key, user_prompt, system_prompt)
            if res:
                return res

        # 3. Offline Copilot Fallback
        q_lower = user_question.lower()
        if "block" in q_lower or "drop" in q_lower:
            return "To block an IP, highlight the connection row and press 'B'. Gort will inject an iptables drop rule in the Linux kernel."
        elif "ignore" in q_lower or "hide" in q_lower:
            return "To hide trusted applications like Chrome or Spotify, highlight the row and press 'I'. You can also ignore entire subnet CIDRs."
        elif "safe" in q_lower or "score" in q_lower:
            return "Gort evaluates every connection with a Zero-Trust score (0-100). Green (80+) is trusted, Yellow (50-79) requires verification, and Red (<50) indicates high risk."
        elif "gemini" in q_lower or "google" in q_lower or "key" in q_lower:
            return "To use your Google Gemini account, set 'export GEMINI_API_KEY=your_key' or save it in '~/.config/myfirewall/config.json'."
        else:
            return (
                f"Gort AI Copilot is currently monitoring {len(active_conns)} active flows. "
                "Highlight any row and press 'E' for an in-depth safety breakdown or 'B' to block."
            )


# Global Singleton
advisor = GortAIAdvisor()
