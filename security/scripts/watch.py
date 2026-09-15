"""Bounded file follower for a single writer/stream. Dry-run only."""

import argparse
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from security.analyzer.engine import Engine
from security.configuration import load_settings
from security.logging import write_record
from security.response.base import AddressPolicy


class CheckpointStore:
    """Atomic log position plus bounded engine state; never stores a log payload."""

    VERSION = 2
    LEGACY_VERSION = 1
    MAX_BYTES = 32 * 1024 * 1024

    def __init__(self, path, input_path):
        self.path = Path(path)
        self.input_path = str(Path(input_path).resolve())
        self.last_payload = None

    def load(self):
        if not self.path.exists():
            return None
        if self.path.stat().st_size > self.MAX_BYTES:
            raise ValueError("Invalid watcher checkpoint")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Invalid watcher checkpoint")
        identity = payload.get("identity")
        values = identity if isinstance(identity, list) else []
        version = payload.get("version")
        if (type(version) is not int or version not in (self.LEGACY_VERSION, self.VERSION)
                or payload.get("input_path") != self.input_path
                or len(values) != 2 or any(type(value) is not int or value < 0 for value in values)
                or type(payload.get("offset")) is not int or payload["offset"] < 0
                or type(payload.get("line_number")) is not int or payload["line_number"] < 0):
            raise ValueError("Invalid watcher checkpoint")
        if version == self.VERSION and not isinstance(payload.get("engine"), dict):
            raise ValueError("Invalid watcher checkpoint")
        self.path.chmod(0o600)
        self.last_payload = payload
        return payload

    def save(self, identity, offset, line_number, engine_state):
        payload = {"version": self.VERSION, "input_path": self.input_path,
                   "identity": list(identity), "offset": offset, "line_number": line_number,
                   "engine": engine_state}
        if payload == self.last_payload:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
                stream.flush()
                if os.fstat(stream.fileno()).st_size > self.MAX_BYTES:
                    raise ValueError("Watcher checkpoint exceeds bounded size")
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name == "posix":
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        self.last_payload = payload


class FileFollower:
    """Retain partial lines, resume offsets, and drain renamed files before switching."""

    def __init__(self, path, limit, resume=None):
        self.path, self.limit = Path(path), limit
        self.stream = None
        self.identity = None
        self.pending = b""
        self.discarding = False
        self.committed_offset = 0
        self.resume = resume
        self.rotation_pending = False
        self.rotation_eof_polls = 0
        self.events = []

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None

    def take_events(self):
        events, self.events = self.events, []
        return events

    def checkpoint_state(self):
        if self.stream is None:
            return None
        return self.identity, self.committed_offset

    def _open(self, path, offset=0):
        stream = Path(path).open("rb")
        opened = os.fstat(stream.fileno())
        if opened.st_size < offset:
            stream.close()
            return False
        stream.seek(offset)
        self.stream = stream
        self.identity = (opened.st_dev, opened.st_ino)
        self.committed_offset = offset
        return True

    def _find_resumed_file(self, identity):
        try:
            candidates = list(self.path.parent.glob(self.path.name + "*"))[:128]
        except OSError:
            return None
        for candidate in candidates:
            try:
                stat = candidate.stat()
            except (FileNotFoundError, OSError):
                continue
            if (stat.st_dev, stat.st_ino) == identity:
                return candidate
        return None

    def _ensure_open(self, current_stat):
        if self.stream is not None:
            return
        current_identity = (current_stat.st_dev, current_stat.st_ino)
        if self.resume is not None:
            wanted = tuple(self.resume["identity"])
            offset = self.resume["offset"]
            candidate = self.path if current_identity == wanted else self._find_resumed_file(wanted)
            if candidate is not None and self._open(candidate, offset):
                self.rotation_pending = self.identity != current_identity
                self.resume = None
                return
            self.events.append("checkpoint_source_missing_or_truncated")
            self.resume = None
        if not self._open(self.path):
            raise OSError("Cannot open input log")

    def _read(self):
        start = self.stream.tell()
        data = self.stream.read(65536)
        output = []
        consumed = 0
        for part in data.splitlines(keepends=True):
            consumed += len(part)
            # Only LF delimits JSONL; splitlines also recognizes CR, so retain it as data.
            if not self.discarding:
                if len(self.pending) + len(part) > self.limit:
                    self.pending = b""
                    self.discarding = True
                else:
                    self.pending += part
            if part.endswith(b"\n"):
                output.append(None if self.discarding else self.pending)
                self.pending, self.discarding = b"", False
                self.committed_offset = start + consumed
        return output, bool(data)

    def _switch_after_rotation(self, output):
        if self.pending or self.discarding:
            output.append(None)
            self.committed_offset = os.fstat(self.stream.fileno()).st_size
            self.pending, self.discarding = b"", False
        self.close()
        self.rotation_pending = False
        self.rotation_eof_polls = 0
        self.events.append("rename_recreate")
        if not self._open(self.path):
            return output
        more, _ = self._read()
        output.extend(more)
        return output

    def poll(self):
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []
        identity = (stat.st_dev, stat.st_ino)
        self._ensure_open(stat)
        if identity == self.identity and stat.st_size < self.stream.tell():
            self.close()
            self.pending = b""
            self.discarding = False
            self.committed_offset = 0
            self.events.append("copytruncate_or_truncation")
            self._open(self.path)
        elif identity != self.identity:
            self.rotation_pending = True

        output, had_data = self._read()
        if self.rotation_pending:
            at_eof = self.stream.tell() >= os.fstat(self.stream.fileno()).st_size
            self.rotation_eof_polls = self.rotation_eof_polls + 1 if at_eof and not had_data else 0
            if self.rotation_eof_polls >= 2:
                output = self._switch_after_rotation(output)
        return output


class Watcher:
    def __init__(self, settings, input_path, audit_path, poll_seconds=0.2, checkpoint_path=None):
        paths = [Path(input_path).resolve(), Path(audit_path).resolve()]
        if checkpoint_path is not None:
            paths.append(Path(checkpoint_path).resolve())
        if len(paths) != len(set(paths)):
            raise ValueError("Input, audit and checkpoint paths must differ")
        if poll_seconds <= 0:
            raise ValueError("Polling interval must be positive")
        self.checkpoint = CheckpointStore(checkpoint_path, input_path) if checkpoint_path else None
        resume = self.checkpoint.load() if self.checkpoint else None
        self.engine = Engine(settings)
        self.state_resumed = bool(resume and resume.get("version") == CheckpointStore.VERSION)
        if self.state_resumed:
            self.engine.restore_state(resume["engine"])
        self.follower = FileFollower(input_path, settings.thresholds["max_line_bytes"], resume)
        self.audit_path = Path(audit_path)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.poll_seconds = poll_seconds
        self.lines = resume["line_number"] if resume else 0
        self.resumed = resume is not None
        self.resume_payload = resume
        self.stop = threading.Event()
        self.error = None

    def _write_records(self, records):
        if not records:
            return
        with self.audit_path.open("a", encoding="utf-8") as stream:
            for record in records:
                write_record(stream, record)
            stream.flush()
            os.fsync(stream.fileno())

    def _save_checkpoint(self):
        if not self.checkpoint:
            return
        state = self.follower.checkpoint_state()
        if state is None and self.resume_payload is not None:
            state = tuple(self.resume_payload["identity"]), self.resume_payload["offset"]
        if state is not None:
            self.checkpoint.save(*state, self.lines, self.engine.export_state())
            self.engine.state_upgraded = False

    def step(self):
        lines = self.follower.poll()
        records = []
        source_events = self.follower.take_events()
        for reason in source_events:
            records.append({"kind": "source_reset", "reason": reason})
            if reason == "checkpoint_source_missing_or_truncated":
                self.engine.reset_state()
                records.append({"kind": "state_reset", "reason": "checkpoint_source_unavailable"})
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
        self._write_records(records)
        legacy = bool(self.checkpoint and self.checkpoint.last_payload
                      and self.checkpoint.last_payload.get("version") == CheckpointStore.LEGACY_VERSION)
        if (lines or source_events or (self.checkpoint and self.checkpoint.last_payload is None)
                or legacy or self.engine.state_upgraded):
            self._save_checkpoint()
        return records

    def reconcile(self, now=None):
        records = self.engine.reconcile(now or datetime.now(timezone.utc))
        self._write_records(records)
        if records:
            self._save_checkpoint()
        return records

    def run(self):
        try:
            with self.audit_path.open("a", encoding="utf-8") as stream:
                write_record(stream, {"kind": "watch_started", "mode": "dry_run",
                                      "resume": "checkpoint" if self.resumed else "from_start",
                                      "state_resume": ("checkpoint_upgrade" if self.engine.state_upgraded else
                                                       "checkpoint" if self.state_resumed else
                                                       "legacy_reset" if self.resumed else "from_start"),
                                      "timestamp": datetime.now(timezone.utc)})
                stream.flush()
                os.fsync(stream.fileno())
            while not self.stop.is_set():
                self.step()
                self.reconcile()
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
    parser.add_argument("--checkpoint", type=Path,
                        help="Atomic log-position and bounded dry-run state checkpoint")
    args = parser.parse_args(argv)
    from dataclasses import replace
    try:
        settings = load_settings(args.config_dir)
        if args.policy:
            settings = replace(settings, policy=AddressPolicy(**json.loads(args.policy.read_text(encoding="utf-8"))))
        watcher = Watcher(settings, args.input, args.audit, checkpoint_path=args.checkpoint)
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
