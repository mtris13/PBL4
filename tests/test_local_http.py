"""Real loopback HTTP integration. No external network or firewall calls."""

import http.client
import json
import socket
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.run import LocalLab


class LocalHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        sockets = [socket.socket(), socket.socket()]
        try:
            for sock in sockets:
                sock.bind(("127.0.0.1", 0))
            cls.proxy_port, cls.backend_port = [sock.getsockname()[1] for sock in sockets]
        finally:
            for sock in sockets:
                sock.close()
        cls.lab = LocalLab({"runtime_dir": str(cls.root), "proxy_port": cls.proxy_port,
                            "backend_port": cls.backend_port, "proxy_source_ip": "127.0.0.2",
                            "trusted_proxies": ["127.0.0.2/32"], "poll_seconds": 0.03})
        cls.lab.start()

    @classmethod
    def tearDownClass(cls):
        cls.lab.close()
        cls.temp.cleanup()

    def get(self, path, headers=None, port=None):
        connection = http.client.HTTPConnection("127.0.0.1", port or self.proxy_port, timeout=5)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_website_over_real_proxy(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Bàn phím Pebble", body.decode())
        self.assertEqual(self.get("/healthz")[0], 200)
        self.assertEqual(self.get("/static/shop.css")[0], 200)

    def test_attacks_reach_audit_without_trusting_spoofed_xff(self):
        for target in ("/?q=UNION+SELECT", "/?q=%3Cscript%3Ealert(1)", "/%252e%252e%252fetc/passwd"):
            self.get(target, {"X-Forwarded-For": "192.0.2.66"})
        for _ in range(21):
            self.get("/healthz")
        deadline = time.monotonic() + 4
        records = []
        while time.monotonic() < deadline:
            path = self.root / "audit.jsonl"
            if path.exists():
                rows = path.read_text(encoding="utf-8").splitlines()
                records = [json.loads(row) for row in rows if row.endswith("}")]
            attacks = {r["detection"]["attack_type"] for r in records if r["kind"] == "detection"}
            if {"sqli", "xss", "path_traversal", "request_flood"} <= attacks:
                break
            time.sleep(0.03)
        self.assertEqual(attacks, {"sqli", "xss", "path_traversal", "request_flood"})
        self.assertTrue(all(r["detection"]["source_ip"] == "127.0.0.1" for r in records if r["kind"] == "detection"))
        self.assertTrue(any(r.get("response", {}).get("outcome") == "suppressed_protected_address" for r in records))
        self.assertTrue(all(not r["response"]["executed"] for r in records if r["kind"] == "response"))
        raw = (self.root / "access.jsonl").read_text(encoding="utf-8")
        self.assertIn('"remote_addr": "127.0.0.2"', raw)
        self.assertIsNone(self.lab.watcher.error)

    def test_direct_backend_header_does_not_change_identity(self):
        self.assertEqual(self.get("/?q=UNION+SELECT", {"X-Forwarded-For": "192.0.2.99"}, self.backend_port)[0], 200)
