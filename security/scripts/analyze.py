import argparse
import sys
from pathlib import Path

from security.analyzer.engine import Engine
from security.configuration import load_settings
from security.logging import write_record
from security.response.dry_run import DryRunAdapter
from security.response.ufw import UfwAdapter
from security.response.iptables import IptablesAdapter
from security.response.aws_waf import AwsWafAdapter


def bounded_lines(stream, limit):
    """Drain oversized lines in bounded chunks without parsing their fragments."""
    while chunk := stream.readline(limit + 1):
        oversized = len(chunk) > limit
        if oversized and not chunk.endswith(b"\n"):
            while remainder := stream.readline(limit + 1):
                if remainder.endswith(b"\n"):
                    break
        yield None if oversized else chunk


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline security core; all responses are previews")
    parser.add_argument("--input", type=Path, required=True, help="Nginx JSONL access log")
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--adapter", choices=("dry-run", "ufw", "iptables", "aws-waf"), default="dry-run")
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config_dir)
        adapters = {"dry-run": lambda: DryRunAdapter(settings.policy), "ufw": lambda: UfwAdapter(settings.policy),
                    "iptables": lambda: IptablesAdapter(settings.policy), "aws-waf": AwsWafAdapter}
        engine = Engine(settings, adapters[args.adapter]())
        counts = {"lines": 0, "invalid_lines": 0, "detections": 0}
        with args.input.open("rb") as stream:
            for number, raw in enumerate(bounded_lines(stream, settings.thresholds["max_line_bytes"]), 1):
                counts["lines"] += 1
                try:
                    if raw is None:
                        raise ValueError
                    line = raw.decode("utf-8")
                except (ValueError, UnicodeError):
                    records = [{"kind": "parse_error", "line_number": number, "reason": "invalid_encoding_or_size"}]
                else:
                    records = engine.process(line, number)
                for record in records:
                    counts["invalid_lines"] += record["kind"] in ("parse_error", "rejected_event")
                    counts["detections"] += record["kind"] == "detection"
                    write_record(sys.stdout, record)
        write_record(sys.stdout, {"kind": "summary", **counts, "active_preview_leases": len(getattr(engine.adapter, "leases", {}))})
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("Cannot load input/configuration; verify paths, permissions and configuration schema.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
