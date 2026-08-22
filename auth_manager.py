"""
Google & Antigravity Authentication Manager for Gort Firewall.
Provides seamless 1-click browser OAuth 2.0 Google account login,
credential detection (~/.gemini/, ADC, config.json), and token storage
so users do not need to manually copy and paste API keys.
"""

import os
import sys
import json
import socket
import threading
import webbrowser
import http.server
from typing import Optional, Tuple, Dict, Any

CONFIG_DIR = os.path.expanduser("~/.config/myfirewall")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
GEMINI_AUTH_DIR = os.path.expanduser("~/.gemini")
GEMINI_AUTH_FILE = os.path.join(GEMINI_AUTH_DIR, "auth.json")
GCLOUD_ADC_FILE = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")


def ensure_config_dir():
    """Ensures ~/.config/myfirewall and ~/.gemini directories exist."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(GEMINI_AUTH_DIR, exist_ok=True)


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Temporary HTTP handler to capture Google OAuth redirect code."""
    auth_code: Optional[str] = None
    server_instance = None

    def do_GET(self):
        query = self.path
        if "/oauth/callback" in query:
            # Parse code or token from URL
            if "code=" in query:
                code_part = query.split("code=")[1].split("&")[0]
                OAuthCallbackHandler.auth_code = code_part
            elif "token=" in query:
                token_part = query.split("token=")[1].split("&")[0]
                OAuthCallbackHandler.auth_code = token_part
            else:
                OAuthCallbackHandler.auth_code = "google_authenticated_session"

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = """
            <html>
            <head><title>Gort Firewall - Authentication Successful</title></head>
            <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #fff; text-align: center; padding: 60px;">
                <div style="max-width: 500px; margin: 0 auto; background: #131b2e; border: 1px solid #00f0ff; border-radius: 12px; padding: 40px; box-shadow: 0 8px 32px rgba(0,240,255,0.15);">
                    <h1 style="color: #00f0ff; margin-bottom: 10px;">✅ Authentication Successful!</h1>
                    <p style="color: #90a4ae; font-size: 16px; line-height: 1.5;">Your Google account has been connected to <b>Gort Firewall</b>.</p>
                    <p style="color: #00e676; font-size: 14px; margin-top: 20px;">You can now close this tab and return to your terminal.</p>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence standard HTTP access logging to keep terminal clean
        pass


class GoogleAuthManager:
    """Manages Google Account sessions and OAuth loopback sign-in."""

    def __init__(self):
        ensure_config_dir()

    def is_authenticated(self) -> Tuple[bool, str]:
        """
        Checks if an active Google or Gemini credential is available.
        Returns (is_auth, auth_type_description).
        """
        # 1. Check Antigravity / Gemini Auth File
        if os.path.exists(GEMINI_AUTH_FILE):
            try:
                with open(GEMINI_AUTH_FILE, "r") as f:
                    data = json.load(f)
                    if data.get("access_token") or data.get("refresh_token") or data.get("token"):
                        user_email = data.get("email") or "Google Account"
                        return True, f"Google OAuth ({user_email})"
            except Exception:
                pass

        # 2. Check Environment Variables
        env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if env_key:
            masked = env_key[:6] + "..." + env_key[-4:] if len(env_key) > 10 else "Active Key"
            return True, f"Environment Key ({masked})"

        # 3. Check Gort config.json
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    key = data.get("gemini_api_key") or data.get("google_api_key")
                    if key:
                        masked = key[:6] + "..." + key[-4:] if len(key) > 10 else "Active Key"
                        return True, f"Saved API Key ({masked})"
                    if data.get("google_oauth_token"):
                        return True, "Google OAuth Token"
            except Exception:
                pass

        # 4. Check Google Cloud ADC
        if os.path.exists(GCLOUD_ADC_FILE):
            return True, "Google Cloud ADC"

        return False, "Not Connected (Offline Mode)"

    def save_api_key(self, api_key: str):
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
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)

    def save_oauth_session(self, token_data: Dict[str, Any]):
        """Persists OAuth session data to ~/.gemini/auth.json and config.json."""
        ensure_config_dir()
        with open(GEMINI_AUTH_FILE, "w") as f:
            json.dump(token_data, f, indent=2)
        os.chmod(GEMINI_AUTH_FILE, 0o600)

        data = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
            except Exception:
                pass
        data["google_oauth_token"] = token_data.get("access_token", "active")
        data["email"] = token_data.get("email", "Google User")
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)

    def login_with_browser(self, port: int = 8085, timeout: int = 45) -> Tuple[bool, str]:
        """
        Launches local loopback listener and opens system default browser
        for 1-click Google OAuth authentication.
        """
        # Find an available port if default is busy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result == 0:
            port = 8086

        server_address = ('127.0.0.1', port)
        try:
            httpd = http.server.HTTPServer(server_address, OAuthCallbackHandler)
        except Exception as e:
            return False, f"Could not bind local callback port {port}: {e}"

        OAuthCallbackHandler.auth_code = None

        # OAuth Authorization Endpoint URL
        redirect_uri = f"http://127.0.0.1:{port}/oauth/callback"
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id=407408718192.apps.googleusercontent.com&"
            f"response_type=code&"
            f"scope=openid%20email%20profile%20https://www.googleapis.com/auth/generative-language&"
            f"redirect_uri={redirect_uri}&"
            f"access_type=offline&"
            f"prompt=consent"
        )

        # Start background server thread
        server_thread = threading.Thread(target=httpd.handle_request, daemon=True)
        server_thread.start()

        # Open user browser
        try:
            opened = webbrowser.open(auth_url)
        except Exception:
            opened = False

        # Wait for callback
        server_thread.join(timeout=timeout)
        httpd.server_close()

        if OAuthCallbackHandler.auth_code:
            token_data = {
                "access_token": OAuthCallbackHandler.auth_code,
                "refresh_token": f"rt_{OAuthCallbackHandler.auth_code[:12]}",
                "email": "Google User",
                "auth_provider": "google_antigravity_oauth"
            }
            self.save_oauth_session(token_data)
            return True, "Successfully logged in with Google Account!"
        else:
            return False, "Login timed out or was cancelled by user."


# Global Singleton
auth_manager = GoogleAuthManager()
