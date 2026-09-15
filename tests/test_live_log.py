import json
import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
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

    def test_checkpoint_restart_skips_committed_lines(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        self.input.write_text(line("/?q=union+select") + "\n", encoding="utf-8")
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertTrue(first.step())
            self.assertEqual(first.lines, 1)
        finally:
            first.follower.close()
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], 2)
        self.assertIn("engine", payload)
        self.assertEqual(payload["offset"], self.input.stat().st_size)
        self.assertEqual(payload["line_number"], 1)
        self.assertNotIn("union", checkpoint.read_text(encoding="utf-8").lower())
        self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o600)

        checkpoint.chmod(0o644)
        resumed = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertTrue(resumed.resumed)
            self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o600)
            self.assertEqual(resumed.lines, 1)
            self.assertEqual(resumed.step(), [])
            with self.input.open("a", encoding="utf-8") as stream:
                stream.write(line(seconds=1) + "\n")
            records = resumed.step()
            decision = next(record for record in records if record["kind"] == "decision")
            self.assertEqual(decision["line_number"], 2)
        finally:
            resumed.follower.close()

    def test_flood_window_persists_across_restart(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        settings = load_settings()
        settings.thresholds["flood"]["request_threshold"] = 3
        self.input.write_text(line(seconds=0) + "\n" + line(seconds=1) + "\n", encoding="utf-8")
        first = Watcher(settings, self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertFalse(any(record.get("kind") == "detection" for record in first.step()))
        finally:
            first.follower.close()

        resumed = Watcher(settings, self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertTrue(resumed.state_resumed)
            with self.input.open("a", encoding="utf-8") as stream:
                stream.write(line(seconds=2) + "\n")
            records = resumed.step()
            attacks = [record["detection"].attack_type for record in records
                       if record["kind"] == "detection"]
            self.assertIn("request_flood", attacks)
        finally:
            resumed.follower.close()

    def test_lease_persists_and_idle_reconciliation_is_durable(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        attack = "/?q=<script>+UNION+SELECT"
        self.input.write_text(line(attack, seconds=0) + "\n", encoding="utf-8")
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            records = first.step()
            self.assertEqual(records[-1]["response"].outcome, "would_block")
        finally:
            first.follower.close()

        resumed = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            with self.input.open("a", encoding="utf-8") as stream:
                stream.write(line(attack, seconds=1) + "\n")
            self.assertEqual(resumed.step()[-1]["response"].outcome, "already_planned")
            records = resumed.reconcile(datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc))
            self.assertTrue(any(record.get("response", {}).outcome == "would_unblock"
                                for record in records if record["kind"] == "response"))
            self.assertTrue(any(record["kind"] == "state_reconciled" for record in records))
        finally:
            resumed.follower.close()

        final = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertEqual(final.engine.adapter.leases, {})
            self.assertEqual(final.reconcile(datetime(2026, 1, 1, 0, 5, 1,
                                                       tzinfo=timezone.utc)), [])
        finally:
            final.follower.close()

    def test_legacy_checkpoint_upgrades_without_claiming_state_resume(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        self.input.write_bytes(b"")
        stat = self.input.stat()
        checkpoint.write_text(json.dumps({"version": 1, "input_path": str(self.input.resolve()),
                                          "identity": [stat.st_dev, stat.st_ino],
                                          "offset": 0, "line_number": 0}), encoding="utf-8")
        watcher = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertTrue(watcher.resumed)
            self.assertFalse(watcher.state_resumed)
            self.assertEqual(watcher.step(), [])
            self.assertEqual(json.loads(checkpoint.read_text())["version"], 2)
        finally:
            watcher.follower.close()

    def test_invalid_engine_state_fails_closed(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        self.input.write_text(line(seconds=0) + "\n", encoding="utf-8")
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            first.step()
        finally:
            first.follower.close()
        valid = json.loads(checkpoint.read_text())
        invalid = []
        missing = deepcopy(valid)
        missing["engine"] = None
        invalid.append(missing)
        bad_address = deepcopy(valid)
        bad_address["engine"]["adapter"]["leases"] = [["not-an-ip", "2026-01-01T00:05:00+00:00"]]
        invalid.append(bad_address)
        config_mismatch = deepcopy(valid)
        config_mismatch["engine"]["flood"]["configuration"]["window_seconds"] = 999
        invalid.append(config_mismatch)
        policy_mismatch = deepcopy(valid)
        policy_mismatch["engine"]["configuration"]["trusted_proxies"] = ["10.0.0.0/24"]
        invalid.append(policy_mismatch)
        naive_time = deepcopy(valid)
        naive_time["engine"]["watermark"] = "2026-01-01T00:00:00"
        invalid.append(naive_time)
        for payload in invalid:
            checkpoint.write_text(json.dumps(payload), encoding="utf-8")
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)

    def test_legacy_engine_state_upgrades_with_preserved_window(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        self.input.write_text(line(seconds=0) + "\n", encoding="utf-8")
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            first.step()
        finally:
            first.follower.close()
        payload = json.loads(checkpoint.read_text())
        payload["engine"]["version"] = 1
        payload["engine"].pop("configuration")
        checkpoint.write_text(json.dumps(payload), encoding="utf-8")
        resumed = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertTrue(resumed.engine.state_upgraded)
            self.assertEqual(len(resumed.engine.flood.windows["198.51.100.23"]), 1)
            self.assertEqual(resumed.step(), [])
            upgraded = json.loads(checkpoint.read_text())
            self.assertEqual(upgraded["engine"]["version"], 2)
            self.assertIn("configuration", upgraded["engine"])
        finally:
            resumed.follower.close()

    def test_missing_checkpoint_source_resets_restored_state(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        self.input.write_text(line(seconds=0) + "\n", encoding="utf-8")
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            first.step()
        finally:
            first.follower.close()
        payload = json.loads(checkpoint.read_text())
        payload["identity"] = [0, 0]
        payload["offset"] = 0
        checkpoint.write_text(json.dumps(payload), encoding="utf-8")
        resumed = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            records = resumed.step()
            self.assertIn({"kind": "state_reset", "reason": "checkpoint_source_unavailable"}, records)
            self.assertEqual(len(resumed.engine.flood.windows["198.51.100.23"]), 1)
        finally:
            resumed.follower.close()

    def test_checkpoint_does_not_skip_an_unfinished_line(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        raw = line(seconds=1).encode()
        self.input.write_bytes(raw)
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            self.assertEqual(first.step(), [])
        finally:
            first.follower.close()
        self.assertEqual(json.loads(checkpoint.read_text())["offset"], 0)
        with self.input.open("ab") as stream:
            stream.write(b"\n")
        resumed = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            records = resumed.step()
            self.assertEqual(sum(record["kind"] == "decision" for record in records), 1)
            self.assertEqual(resumed.lines, 1)
        finally:
            resumed.follower.close()

    def test_rename_rotation_drains_old_inode_before_new_file(self):
        rotated = self.root / "access.jsonl.1"
        self.input.write_text(line(seconds=0) + "\n", encoding="utf-8")
        self.watcher.step()
        self.input.rename(rotated)
        self.input.write_text(line(seconds=2) + "\n", encoding="utf-8")

        self.assertEqual(self.watcher.step(), [])
        with rotated.open("a", encoding="utf-8") as stream:
            stream.write(line(seconds=1) + "\n")
        late_records = self.watcher.step()
        late_decision = next(record for record in late_records if record["kind"] == "decision")
        self.assertEqual(late_decision["line_number"], 2)
        self.assertEqual(self.watcher.step(), [])
        new_records = self.watcher.step()
        self.assertEqual(new_records[0], {"kind": "source_reset", "reason": "rename_recreate"})
        new_decision = next(record for record in new_records if record["kind"] == "decision")
        self.assertEqual(new_decision["line_number"], 3)

    def test_checkpoint_finds_a_rotated_inode_after_restart(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        rotated = self.root / "access.jsonl.1"
        self.input.write_text(line(seconds=0) + "\n", encoding="utf-8")
        first = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            first.step()
        finally:
            first.follower.close()
        self.input.rename(rotated)
        with rotated.open("a", encoding="utf-8") as stream:
            stream.write(line(seconds=1) + "\n")
        self.input.write_text(line(seconds=2) + "\n", encoding="utf-8")

        resumed = Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        try:
            late_records = resumed.step()
            late_decision = next(record for record in late_records if record["kind"] == "decision")
            self.assertEqual(late_decision["line_number"], 2)
            self.assertEqual(resumed.step(), [])
            new_records = resumed.step()
            self.assertEqual(new_records[0], {"kind": "source_reset", "reason": "rename_recreate"})
            new_decision = next(record for record in new_records if record["kind"] == "decision")
            self.assertEqual(new_decision["line_number"], 3)
        finally:
            resumed.follower.close()

    def test_invalid_or_rebound_checkpoint_fails_closed(self):
        checkpoint = self.root / "watcher.checkpoint.json"
        for invalid in ("{}", "[]", '{"version":true}'):
            checkpoint.write_text(invalid, encoding="utf-8")
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)
        checkpoint.write_text(json.dumps({"version": 1, "input_path": "/different/input",
                                          "identity": [1, 2], "offset": 0, "line_number": 0}),
                              encoding="utf-8")
        with self.assertRaises(ValueError):
            Watcher(load_settings(), self.input, self.output, checkpoint_path=checkpoint)

    def test_reject_same_input_output(self):
        with self.assertRaises(ValueError):
            Watcher(load_settings(), self.input, self.input)
        with self.assertRaises(ValueError):
            Watcher(load_settings(), self.input, self.output, checkpoint_path=self.input)

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
