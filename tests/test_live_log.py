import json
import unittest
from dataclasses import replace
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.access_log import AccessLogMiddleware, redact_target
from lab.proxy import build_proxy_headers
from security.analyzer.parsers.nginx_json import NginxJsonParser
from security.configuration import load_settings
from security.response.base import AddressPolicy
from security.scripts.watch import FileFollower, Watcher
from security.tests.helpers import line
from shop.app import create_app


class LiveLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.input = self.root / "access.jsonl"
        self.output = self.root / "audit.jsonl"
        self.watcher = Watcher(load_settings(), self.input, self.output)

    def tearDown(self):
        self.watcher.follower.close()
        self.temp.cleanup()

    def test_append_partial_lines_no_duplicates(self):
        self.assertEqual(self.watcher.step(), [])
        raw = (line("/?q=union+select") + "\n").encode()
        self.input.write_bytes(raw[:30])
        self.assertEqual(self.watcher.step(), [])
        with self.input.open("ab") as stream:
            stream.write(raw[30:])
        records = self.watcher.step()
        self.assertEqual(records[0]["detection"].attack_type, "sqli")
        self.assertEqual(self.watcher.step(), [])
        self.assertEqual(self.watcher.lines, 1)

    def test_oversized_and_encoding_recovery(self):
        self.input.write_bytes(b"x" * 70000 + b"\n\xff\n" + line().encode() + b"\n")
        records = self.watcher.step() + self.watcher.step()
        self.assertEqual(sum(r["kind"] == "parse_error" for r in records), 2)
        self.assertEqual(sum(r["kind"] == "decision" for r in records), 1)

    def test_truncation_resets_and_audits(self):
        self.input.write_text(line() + "\n", encoding="utf-8")
        self.watcher.step()
        self.input.write_bytes(b"bad\n")
        records = self.watcher.step()
        self.assertEqual(records[0]["kind"], "source_reset")
        self.assertEqual(records[1]["kind"], "parse_error")

    def test_reject_same_input_output(self):
        with self.assertRaises(ValueError):
            Watcher(load_settings(), self.input, self.input)

    def test_redaction(self):
        target = redact_target("/?q=book&password=secret&access_token=secret&secret=secret&category=desk")
        self.assertNotIn("secret", target)
        self.assertNotIn("password", target)
        self.assertIn("q=book", target)

    def test_proxy_appends_and_removes_spoofed_host(self):
        headers = Message()
        headers["X-Forwarded-For"] = "192.0.2.66"
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = "evil.test"
        headers["Connection"] = "X-Extra"
        headers["X-Extra"] = "discard"
        result = build_proxy_headers(headers, "198.51.100.23", "127.0.0.1:8080")
        self.assertEqual(result["X-Forwarded-For"], "192.0.2.66, 198.51.100.23")
        self.assertEqual(result["X-Forwarded-Proto"], "http")
        self.assertNotIn("X-Forwarded-Host", result)
        self.assertNotIn("X-Extra", result)

    def test_target_log_to_audit_with_trusted_proxy(self):
        app = create_app({"TESTING": True, "SECRET_KEY": "test-secret-" * 4,
                          "DATABASE": str(self.root / "shop.sqlite3"), "SESSION_COOKIE_SECURE": False})
        app.wsgi_app = AccessLogMiddleware(app.wsgi_app, self.input)
        client = app.test_client()
        response = client.get("/?q=%3Cscript%3E+UNION+SELECT&token=PRIVATE_VALUE",
                              headers={"X-Forwarded-For": "192.0.2.1, 198.51.100.23", "Cookie": "PRIVATE_VALUE"},
                              environ_overrides={"REMOTE_ADDR": "127.0.0.2"})
        response.get_data()
        response.close()
        settings = replace(load_settings(), policy=AddressPolicy(trusted_proxies=["127.0.0.2/32"]))
        watcher = Watcher(settings, self.input, self.output)
        try:
            records = watcher.step()
            result = records[-1]["response"]
            self.assertEqual(result.source_ip, "198.51.100.23")
            self.assertEqual(result.outcome, "would_block")
            self.assertFalse(result.executed)
            self.assertNotIn("PRIVATE_VALUE", self.input.read_text())
            self.assertNotIn("PRIVATE_VALUE", self.output.read_text())
        finally:
            watcher.follower.close()

    def test_local_proxy_and_client_have_distinct_trust_roles(self):
        parser = NginxJsonParser(AddressPolicy(trusted_proxies=["127.0.0.2/32"]))
        request = parser.parse(line(remote_addr="127.0.0.2", http_x_forwarded_for="192.0.2.66, 127.0.0.1"))
        self.assertEqual(request.source_ip, "127.0.0.1")
        direct = parser.parse(line(remote_addr="127.0.0.1", http_x_forwarded_for="192.0.2.66"))
        self.assertEqual(direct.source_ip, "127.0.0.1")
