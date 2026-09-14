"""Bounded file follower for a single writer/stream. Dry-run only."""

import argparse
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from security.analyzer.engine import Engine
from security.configuration import load_settings
from security.logging import write_record
from security.response.base import AddressPolicy


class FileFollower:
    """Retains partial lines; detects rename/recreate and ordinary truncation.

    No durable checkpoint yet. Restart replays from the beginning by design.
    Use rename/recreate rotation: copytruncate can lose writes between polls.
    """
    def __init__(self, path, limit):
        self.path, self.limit = Path(path), limit
        self.stream = None
        self.identity = None
        self.pending = b""
        self.discarding = False
        self.resets = 0

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None

    def poll(self):
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []
        identity = (stat.st_dev, stat.st_ino)
        if self.stream is not None and (identity != self.identity or stat.st_size < self.stream.tell()):
            self.close()
            self.pending = b""
            self.discarding = False
            self.resets += 1
        if self.stream is None:
            self.stream = self.path.open("rb")
            opened = os.fstat(self.stream.fileno())
            self.identity = (opened.st_dev, opened.st_ino)
        data = self.stream.read(65536)
        output = []
        for part in data.splitlines(keepends=True):
            # Only LF delimits JSONL; splitlines also recognizes CR, so treat it as data.
            if not self.discarding:
                self.pending += part
                if len(self.pending) > self.limit:
                    self.pending = b""
                    self.discarding = True
            if part.endswith(b"\n"):
                output.append(None if self.discarding else self.pending)
                self.pending, self.discarding = b"", False
        return output


class Watcher:
    def __init__(self, settings, input_path, audit_path, poll_seconds=0.2):
        if Path(input_path).resolve() == Path(audit_path).resolve():
            raise ValueError("Input and audit paths must differ")
        if poll_seconds <= 0:
            raise ValueError("Polling interval must be positive")
        self.engine = Engine(settings)
        self.follower = FileFollower(input_path, settings.thresholds["max_line_bytes"])
        self.audit_path = Path(audit_path)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.poll_seconds = poll_seconds
        self.lines = 0
        self.stop = threading.Event()
        self.error = None

    def step(self):
        old_resets = self.follower.resets
        lines = self.follower.poll()
        records = []
        if self.follower.resets != old_resets:
            records.append({"kind": "source_reset", "reason": "rotation_or_truncation"})
        for raw in lines:
            self.lines += 1
            try:
                if raw is None:
                    raise ValueError
                line = raw.decode("utf-8")
            except (ValueError, UnicodeError):
                records.append({"kind": "parse_error", "line_number": self.lines, "reason": "invalid_encoding_or_size"})
            else:
                records.extend(self.engine.process(line, self.lines))
        if records:
            with self.audit_path.open("a", encoding="utf-8") as stream:
                for record in records:
                    write_record(stream, record)
        return records

    def run(self):
        try:
            with self.audit_path.open("a", encoding="utf-8") as stream:
                write_record(stream, {"kind": "watch_started", "mode": "dry_run", "replay": "from_start",
                                      "timestamp": datetime.now(timezone.utc)})
            while not self.stop.is_set():
                self.step()
                self.stop.wait(self.poll_seconds)
        except Exception as error:
            self.error = type(error).__name__  # Do not log exception contents or payloads.
        finally:
            self.follower.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Follow Nginx JSONL; dry-run only")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--policy", type=Path, help="Optional complete address-policy JSON override")
    args = parser.parse_args(argv)
    import json
    from dataclasses import replace
    try:
        settings = load_settings(args.config_dir)
        if args.policy:
            settings = replace(settings, policy=AddressPolicy(**json.loads(args.policy.read_text(encoding="utf-8"))))
        watcher = Watcher(settings, args.input, args.audit)
        watcher.run()
        if watcher.error:
            print("Watcher stopped because of an input/output or processing error.")
            return 2
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("Cannot start watcher; check input, output and configuration.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
