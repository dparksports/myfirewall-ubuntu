"""
Unit tests for GoogleAuthManager and OAuth loopback sign-in logic.
"""

import os
import json
import tempfile
import unittest
from unittest.mock import patch

import auth_manager as am


class TestGoogleAuthManager(unittest.TestCase):
    """Test suite for authentication management."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.original_config_file = am.CONFIG_FILE
        self.original_auth_file = am.GEMINI_AUTH_FILE
        am.CONFIG_FILE = os.path.join(self.temp_dir, "config.json")
        am.GEMINI_AUTH_FILE = os.path.join(self.temp_dir, "auth.json")
        am.CONFIG_DIR = self.temp_dir
        am.GEMINI_AUTH_DIR = self.temp_dir

    def tearDown(self):
        am.CONFIG_FILE = self.original_config_file
        am.GEMINI_AUTH_FILE = self.original_auth_file

    def test_unauthenticated_default(self):
        """Verify default unauthenticated state when no keys/tokens are present."""
        with patch.dict(os.environ, {}, clear=True):
            auth_mgr = am.GoogleAuthManager()
            is_auth, desc = auth_mgr.is_authenticated()
            self.assertFalse(is_auth)
            self.assertIn("Not Connected", desc)

    def test_environment_variable_detection(self):
        """Verify detection of GEMINI_API_KEY from environment."""
        with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyTestApiKey1234567890"}, clear=True):
            auth_mgr = am.GoogleAuthManager()
            is_auth, desc = auth_mgr.is_authenticated()
            self.assertTrue(is_auth)
            self.assertIn("Environment Key", desc)

    def test_save_and_detect_api_key(self):
        """Verify saving and detecting API keys from config.json."""
        auth_mgr = am.GoogleAuthManager()
        auth_mgr.save_api_key("AIzaSyManualConfigKey987654321")

        is_auth, desc = auth_mgr.is_authenticated()
        self.assertTrue(is_auth)
        self.assertIn("Saved API Key", desc)

    def test_oauth_session_persistence(self):
        """Verify OAuth session saving and detection."""
        auth_mgr = am.GoogleAuthManager()
        token_data = {
            "access_token": "ya29.sample_oauth_access_token",
            "refresh_token": "rt_sample_refresh_token",
            "email": "developer@example.com"
        }
        auth_mgr.save_oauth_session(token_data)

        is_auth, desc = auth_mgr.is_authenticated()
        self.assertTrue(is_auth)
        self.assertIn("Google OAuth", desc)
        self.assertIn("developer@example.com", desc)


if __name__ == '__main__':
    unittest.main()
