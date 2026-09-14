import io
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory

from security.analyzer.engine import Engine
from security.configuration import load_settings
from security.logging import write_record
from security.scripts.analyze import bounded_lines, main
from security.tests.helpers import line


SAMPLES = Path(__file__).resolve().parents[1] / "sample_logs"


class PipelineTests(unittest.TestCase):
    def test_default_dry_run_and_audit_redaction(self):
        raw = line("/?password=VERY_SECRET&token=VERY_SECRET&q=<script> UNION SELECT password",
                   http_user_agent="VERY_SECRET", request_id="VERY_SECRET", cookie="VERY_SECRET")
        records = Engine(load_settings()).process(raw)
        stream = io.StringIO()
        for record in records:
            write_record(stream, record)
        self.assertNotIn("VERY_SECRET", stream.getvalue())
        self.assertNotIn("<script>", stream.getvalue())
        self.assertEqual(records[-1]["response"].outcome, "would_block")
        self.assertEqual(records[-1]["response"].adapter, "dry_run")

    def test_malformed_then_valid(self):
        engine = Engine(load_settings())
        self.assertEqual(engine.process("secret-invalid")[0]["kind"], "parse_error")
        self.assertEqual(engine.process(line())[-1]["response"].action, "observe")

    def test_out_of_order_rejected_without_state_change(self):
        engine = Engine(load_settings())
        engine.process(line(seconds=10))
        self.assertEqual(engine.process(line(seconds=9))[0]["reason"], "out_of_order_timestamp")
        self.assertEqual(len(engine.flood.windows["198.51.100.23"]), 1)

    def test_pipeline_expiry(self):
        engine = Engine(load_settings())
        engine.process(line("/?q=<script> UNION SELECT"))
        records = engine.process(line(seconds=300))
        self.assertEqual(records[0]["response"].action, "unblock")

    def test_capacity_warning(self):
        settings = load_settings()
        settings.thresholds["flood"]["max_sources"] = 1
        engine = Engine(settings)
        engine.process(line())
        records = engine.process(line(remote_addr="203.0.113.4"))
        self.assertTrue(any(r["kind"] == "capacity_warning" for r in records))

    def test_bounded_reader_recovers(self):
        self.assertEqual(list(bounded_lines(io.BytesIO(b"x" * 200 + b"\nok\n"), 10)), [None, b"ok\n"])

    def test_cli_samples_all_attacks(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = main(["--input", str(SAMPLES / "mixed.jsonl")])
        self.assertEqual(code, 0)
        records = [json.loads(row) for row in stream.getvalue().splitlines()]
        attacks = {r["detection"]["attack_type"] for r in records if r["kind"] == "detection"}
        self.assertEqual(attacks, {"sqli", "xss", "path_traversal", "request_flood"})
        self.assertEqual(records[-1]["invalid_lines"], 1)
        self.assertTrue(any(r.get("response", {}).get("outcome") == "would_block" for r in records))
        self.assertTrue(all(not r["response"]["executed"] for r in records if r["kind"] == "response"))

    def test_cli_bad_encoding_recovers(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "test.jsonl"
            path.write_bytes(b"\xff\n" + line().encode() + b"\n")
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(main(["--input", str(path)]), 0)
            self.assertEqual(json.loads(stream.getvalue().splitlines()[-1])["invalid_lines"], 1)

    def test_cli_missing_file(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--input", str(SAMPLES / "missing.jsonl")]), 2)

    def test_invalid_config_fails_early(self):
        root = Path(__file__).resolve().parents[2] / "config"
        with TemporaryDirectory() as directory:
            target = Path(directory)
            for path in root.glob("*.yaml"):
                (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            thresholds = json.loads((target / "thresholds.yaml").read_text())
            thresholds["flood"]["window_seconds"] = 0
            (target / "thresholds.yaml").write_text(json.dumps(thresholds))
            with self.assertRaises(ValueError):
                load_settings(target)
