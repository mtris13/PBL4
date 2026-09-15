import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.demo import audit_offset, audit_records_since


class DemoAuditTests(unittest.TestCase):
    def test_reads_only_complete_records_appended_after_baseline(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            old = {"kind": "detection", "detection": {"attack_type": "old"}}
            new = {"kind": "detection", "detection": {"attack_type": "sqli"}}
            path.write_text(json.dumps(old) + "\n", encoding="utf-8")
            offset = audit_offset(path)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(new) + "\n")
                stream.write('{"unfinished":')
            self.assertEqual(audit_records_since(path, offset), [new])

    def test_baseline_keeps_an_unfinished_tail(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_bytes(b'{"kind":"det')
            self.assertEqual(audit_offset(path), 0)
