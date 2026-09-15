import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from security.scripts.rotate_logs import rotate_logs


@unittest.skipUnless(sys.platform.startswith("linux"), "Arch log rotator requires Linux")
class LogRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.access = self.root / "access.jsonl"
        self.audit = self.root / "audit.jsonl"
        self.checkpoint = self.root / "watcher.checkpoint.json"
        self.pid = self.root / "nginx.pid"
        self.pid.write_text("123\n", encoding="ascii")
        self.now = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temp.cleanup()

    def checkpoint_active(self):
        metadata = self.access.stat()
        self.checkpoint.write_text(json.dumps({
            "version": 2,
            "input_path": str(self.access.resolve()),
            "identity": [metadata.st_dev, metadata.st_ino],
            "offset": metadata.st_size,
            "line_number": 1,
            "engine": {},
        }), encoding="utf-8")

    def run_rotation(self, **overrides):
        options = {"access_path": self.access, "audit_path": self.audit,
                   "checkpoint_path": self.checkpoint, "nginx_pid_path": self.pid,
                   "max_bytes": 4, "keep": 2, "now": self.now,
                   "reopen": lambda path: self.assertEqual(path, self.pid)}
        options.update(overrides)
        return rotate_logs(**options)

    def test_rename_rotation_reopens_access_and_secures_new_files(self):
        self.access.write_text("access-record\n", encoding="utf-8")
        self.audit.write_text("audit-record\n", encoding="utf-8")
        self.checkpoint_active()

        report = self.run_rotation()

        self.assertEqual(report["access"]["action"], "rotated")
        self.assertEqual(report["audit"]["action"], "rotated")
        self.assertEqual(self.access.read_bytes(), b"")
        self.assertEqual(self.audit.read_bytes(), b"")
        self.assertEqual((self.root / report["access"]["file"]).read_text(), "access-record\n")
        self.assertEqual((self.root / report["audit"]["file"]).read_text(), "audit-record\n")
        if os.name == "posix":
            self.assertEqual(self.access.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.audit.stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.root / "logrotate.lock").stat().st_mode & 0o777, 0o600)

    def test_access_waits_for_watcher_but_audit_can_rotate(self):
        self.access.write_text("access-record\n", encoding="utf-8")
        self.audit.write_text("audit-record\n", encoding="utf-8")
        self.checkpoint.write_text(json.dumps({
            "version": 2, "input_path": str(self.access.resolve()),
            "identity": [0, 0], "offset": 0, "line_number": 0, "engine": {},
        }), encoding="utf-8")

        report = self.run_rotation(reopen=lambda path: self.fail("must not reopen"))

        self.assertEqual(report["access"]["action"], "watcher_not_on_active_file")
        self.assertEqual(self.access.read_text(), "access-record\n")
        self.assertEqual(report["audit"]["action"], "rotated")

    def test_failed_nginx_reopen_rolls_access_back_without_data_loss(self):
        self.access.write_text("access-record\n", encoding="utf-8")
        self.audit.write_text("audit-record\n", encoding="utf-8")
        original_identity = (self.access.stat().st_dev, self.access.stat().st_ino)
        self.checkpoint_active()

        def fail_reopen(_):
            raise OSError("simulated")

        with self.assertRaises(OSError):
            self.run_rotation(reopen=fail_reopen)
        self.assertEqual(self.access.read_text(), "access-record\n")
        self.assertEqual((self.access.stat().st_dev, self.access.stat().st_ino), original_identity)
        self.assertEqual(list(self.root.glob("access.jsonl.20*")), [])
        self.assertEqual(self.audit.read_text(), "audit-record\n")

    def test_retention_is_bounded_and_preserves_checkpoint_inode(self):
        self.access.write_text("active\n", encoding="utf-8")
        protected = self.root / "access.jsonl.20260913T120000Z"
        removable = self.root / "access.jsonl.20260914T120000Z"
        newest = self.root / "access.jsonl.20260915T120000Z"
        for path in (protected, removable, newest):
            path.write_text(path.name, encoding="utf-8")
        protected_stat = protected.stat()
        self.checkpoint.write_text(json.dumps({
            "version": 2, "input_path": str(self.access.resolve()),
            "identity": [protected_stat.st_dev, protected_stat.st_ino],
            "offset": 0, "line_number": 0, "engine": {},
        }), encoding="utf-8")

        report = self.run_rotation(max_bytes=1000, keep=1)

        self.assertEqual(report["access"]["action"], "below_threshold")
        self.assertTrue(newest.exists())
        self.assertTrue(protected.exists())
        self.assertFalse(removable.exists())
        self.assertEqual(report["access"]["removed"], [removable.name])

    def test_repeated_rotation_keeps_only_configured_generations(self):
        for generation in range(4):
            self.access.write_text(f"access-{generation}\n", encoding="utf-8")
            self.audit.write_text(f"audit-{generation}\n", encoding="utf-8")
            self.checkpoint_active()
            self.run_rotation(now=self.now + timedelta(seconds=generation))
        self.assertEqual(len(list(self.root.glob("access.jsonl.20*"))), 2)
        self.assertEqual(len(list(self.root.glob("audit.jsonl.20*"))), 2)


if __name__ == "__main__":
    unittest.main()
