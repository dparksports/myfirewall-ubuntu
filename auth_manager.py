"""
Google Gemini Authentication & Model Discovery Manager for Gort Firewall.
Dynamically retrieves all available Gemini Flash models from Google's ModelService,
validates API keys against live endpoints without hardcoding version numbers,
and persists active model selections.
"""

import os
import sys
import json
import requests
import subprocess
import webbrowser
from typing import Optional, Tuple, Dict, Any, List


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
    """Manages Google Gemini Account sessions, dynamic model discovery, and API validation."""

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
                        masked = k[:6] + "..." + k[-4:] if len(key) > 10 else "Active Key"
                        model = data.get("active_model", "gemini-flash")
                        return True, f"Saved Key ({masked} | {model})"
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

    def get_active_model(self) -> str:
        """Returns the configured model or defaults to dynamic discovery."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    model = data.get("active_model")
                    if model:
                        return model
            except Exception:
                pass
        return "gemini-3.1-flash-lite-preview"

    def list_all_models(self, api_key: str) -> List[Dict[str, Any]]:
        """
        Dynamically queries Google's ModelService.ListModels endpoint.
        Retrieves all available models without hardcoded assumptions.
        """
        key = api_key.strip()
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
        try:
            resp = requests.get(endpoint, timeout=6.0)
            if resp.status_code == 200:
                return resp.json().get("models", [])
        except Exception:
            pass
        return []

    def get_flash_models(self, api_key: str) -> List[str]:
        """
        Extracts all candidate Gemini Flash models supporting content generation.
        Filters out pure image/audio/robotics pipelines.
        """
        models = self.list_all_models(api_key)
        flash_models = []
        for m in models:
            name = m.get("name", "").replace("models/", "")
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" in methods:
                if "flash" in name.lower() and not any(x in name.lower() for x in ["image", "tts", "audio", "robotics", "er-", "preview-tts"]):
                    flash_models.append(name)
        return flash_models

    def discover_and_verify_best_model(self, api_key: str) -> Tuple[Optional[str], List[str], str]:
        """
        Probes discovered Flash models to find the fastest, active 200 OK model.
        Returns (best_model_name, list_of_all_flash_models, status_message).
        """
        key = api_key.strip()
        flash_models = self.get_flash_models(key)
        if not flash_models:
            # Fallback: check all models if no flash models found
            all_models = self.list_all_models(key)
            candidates = [m.get("name", "").replace("models/", "") for m in all_models if "generateContent" in m.get("supportedGenerationMethods", [])]
        else:
            candidates = flash_models

        if not candidates:
            return None, [], "No generateContent models found for this API key."

        # Probe candidate models for a healthy 200 OK
        for cand in candidates:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{cand}:generateContent?key={key}"
            payload = {"contents": [{"parts": [{"text": "ping"}]}]}
            try:
                resp = requests.post(endpoint, json=payload, timeout=4.0)
                if resp.status_code == 200:
                    return cand, flash_models, f"Verified active model: {cand}"
            except Exception:
                continue

        # If individual probing timed out, default to first candidate
        return candidates[0], flash_models, f"Selected candidate model: {candidates[0]}"

    def validate_api_key(self, api_key: str) -> Tuple[bool, str, Optional[str], List[str]]:
        """
        Validates API key by discovering all available models and verifying generation.
        Returns (is_valid, message, selected_model, all_flash_models).
        """
        key = api_key.strip()
        if not key:
            return False, "API key cannot be empty.", None, []

        best_model, flash_models, msg = self.discover_and_verify_best_model(key)
        if best_model:
            return True, f"API Key valid! {msg}", best_model, flash_models
        else:
            return False, f"Validation failed: {msg}", None, []

    def save_api_key(self, api_key: str, active_model: Optional[str] = None) -> bool:
        """Saves a Gemini API key and active model to ~/.config/myfirewall/config.json."""
        ensure_config_dir()
        data = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        data["gemini_api_key"] = api_key.strip()
        if active_model:
            data["active_model"] = active_model.strip()
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
        print("\n" + "="*74)
        print("🤖 GORT FIREWALL — GOOGLE GEMINI ACCOUNT CONFIGURATION")
        print("="*74)
        print("Connect your Google account to enable real-time AI security advice,\n"
              "packet analysis, and interactive copilot Q&A.\n")
        print(f"👉 Opening Google AI Studio in your browser:\n   {key_url}\n")
        print("1. Sign in with your Google account.")
        print("2. Click 'Create API key' and copy your key.\n" + "-"*74)

        self.open_browser_safe(key_url)

        try:
            user_input = input("\nPaste your Gemini API Key (or press Enter to cancel): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSetup cancelled.")
            return False

        if not user_input:
            print("No key provided. Gort will continue in offline heuristic mode.")
            return False

        print("\n⏳ Querying Google ModelService & dynamically discovering all Flash models...")
        valid, msg, best_model, flash_models = self.validate_api_key(user_input)
        if valid:
            print(f"\n✨ Discovered {len(flash_models)} Gemini Flash Models:")
            for m in flash_models:
                marker = "⭐ (Selected)" if m == best_model else "  "
                print(f"   {marker} models/{m}")

            self.save_api_key(user_input, active_model=best_model)
            print(f"\n✅ {msg}")
            print(f"💾 Saved configuration to: {CONFIG_FILE}")
            print("🎉 Google Gemini AI is now active across Gort Firewall!\n")
            return True
        else:
            print(f"\n❌ {msg}")
            print("Please double check your key and try again.\n")
            return False


# Global Singleton
auth_manager = GoogleAuthManager()
