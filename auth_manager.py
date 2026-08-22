"""
Google Gemini Authentication Manager for Gort Firewall.
Provides seamless Google account setup via Google AI Studio,
environment variables, configuration file persistence, and live key validation.
"""

import os
import sys
import json
import requests
import subprocess
import webbrowser
from typing import Optional, Tuple, Dict, Any


def get_user_home() -> str:
    """Returns the actual user's home directory even when executed under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return pwd.getpwnam(sudo_user).pw_dir
        except Exception:
            return os.path.expanduser(f"~{sudo_user}")
    return os.path.expanduser("~")


HOME_DIR = get_user_home()
CONFIG_DIR = os.path.join(HOME_DIR, ".config/myfirewall")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
GEMINI_AUTH_DIR = os.path.join(HOME_DIR, ".gemini")
GEMINI_AUTH_FILE = os.path.join(GEMINI_AUTH_DIR, "auth.json")
GCLOUD_ADC_FILE = os.path.join(HOME_DIR, ".config/gcloud/application_default_credentials.json")


def ensure_config_dir():
    """Ensures configuration and auth directories exist with proper permissions."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(GEMINI_AUTH_DIR, exist_ok=True)


class GoogleAuthManager:
    """Manages Google Gemini Account sessions, API keys, and validation."""

    def __init__(self):
        ensure_config_dir()

    def is_authenticated(self) -> Tuple[bool, str]:
        """
        Checks if an active Google or Gemini credential is available.
        Returns (is_auth, auth_type_description).
        """
        # 1. Check Environment Variables
        env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if env_key and len(env_key.strip()) > 5:
            k = env_key.strip()
            masked = k[:6] + "..." + k[-4:] if len(k) > 10 else "Active Key"
            return True, f"Environment Key ({masked})"

        # 2. Check Gort config.json
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    key = data.get("gemini_api_key") or data.get("google_api_key")
                    if key and len(key.strip()) > 5:
                        k = key.strip()
                        masked = k[:6] + "..." + k[-4:] if len(k) > 10 else "Active Key"
                        return True, f"Saved Gemini Key ({masked})"
            except Exception:
                pass

        # 3. Check Antigravity / Gemini Auth File
        if os.path.exists(GEMINI_AUTH_FILE):
            try:
                with open(GEMINI_AUTH_FILE, "r") as f:
                    data = json.load(f)
                    if data.get("access_token") or data.get("refresh_token") or data.get("token"):
                        user_email = data.get("email") or "Google Account"
                        return True, f"Google Session ({user_email})"
            except Exception:
                pass

        # 4. Check Google Cloud ADC
        if os.path.exists(GCLOUD_ADC_FILE):
            return True, "Google Cloud ADC"

        return False, "Not Connected (Offline Heuristic Mode)"

    def get_api_key(self) -> Optional[str]:
        """Returns the active Gemini API Key if available."""
        env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if env_key and len(env_key.strip()) > 5:
            return env_key.strip()

        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    key = data.get("gemini_api_key") or data.get("google_api_key")
                    if key and len(key.strip()) > 5:
                        return key.strip()
            except Exception:
                pass
        return None

    def validate_api_key(self, api_key: str) -> Tuple[bool, str]:
        """Performs a lightweight validation test request to Google Gemini API."""
        key = api_key.strip()
        if not key:
            return False, "API key cannot be empty."

        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
        payload = {
            "contents": [{"parts": [{"text": "Hello, confirm connection."}]}]
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=8.0)
            if resp.status_code == 200:
                return True, "API Key is valid and active!"
            else:
                error_data = resp.json().get("error", {})
                error_msg = error_data.get("message", f"HTTP {resp.status_code}")
                return False, f"Google API Error: {error_msg}"
        except Exception as e:
            return False, f"Connection failed: {e}"

    def save_api_key(self, api_key: str) -> bool:
        """Saves a Gemini API key to ~/.config/myfirewall/config.json."""
        ensure_config_dir()
        data = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        data["gemini_api_key"] = api_key.strip()
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(CONFIG_FILE, 0o600)
            return True
        except Exception:
            return False

    def save_oauth_session(self, token_data: Dict[str, Any]) -> bool:
        """Persists OAuth session data to ~/.gemini/auth.json and config.json."""
        ensure_config_dir()
        try:
            with open(GEMINI_AUTH_FILE, "w") as f:
                json.dump(token_data, f, indent=2)
            os.chmod(GEMINI_AUTH_FILE, 0o600)
            return True
        except Exception:
            return False

    def open_browser_safe(self, url: str) -> bool:
        """Safely opens a URL in the user's default browser."""
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and hasattr(os, "geteuid") and os.geteuid() == 0:
            try:
                subprocess.Popen(["sudo", "-u", sudo_user, "xdg-open", url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                pass
        try:
            return webbrowser.open(url)
        except Exception:
            return False

    def interactive_terminal_login(self) -> bool:
        """Runs an interactive terminal setup wizard for Google Gemini."""
        key_url = "https://aistudio.google.com/app/apikey"
        print("\n" + "="*72)
        print("🤖 GORT FIREWALL — GOOGLE GEMINI ACCOUNT CONFIGURATION")
        print("="*72)
        print("Connect your Google account to enable real-time AI security advice,\n"
              "packet analysis, and interactive copilot Q&A.\n")
        print(f"👉 Opening Google AI Studio in your browser:\n   {key_url}\n")
        print("1. Sign in with your Google account.")
        print("2. Click 'Create API key' and copy your key.\n" + "-"*72)

        self.open_browser_safe(key_url)

        try:
            user_input = input("\nPaste your Gemini API Key (or press Enter to cancel): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSetup cancelled.")
            return False

        if not user_input:
            print("No key provided. Gort will continue in offline heuristic mode.")
            return False

        print("\n⏳ Validating key with Google Gemini API...")
        valid, msg = self.validate_api_key(user_input)
        if valid:
            self.save_api_key(user_input)
            print(f"✅ {msg}")
            print(f"💾 Saved to: {CONFIG_FILE}")
            print("🎉 Google Gemini AI is now active across Gort Firewall!\n")
            return True
        else:
            print(f"❌ {msg}")
            print("Please double check your key and try again.\n")
            return False


# Global Singleton
auth_manager = GoogleAuthManager()
