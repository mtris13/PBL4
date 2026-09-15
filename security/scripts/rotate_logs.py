"""Bounded rename/reopen rotation for the single-writer Arch lab logs."""

import argparse
import json
import os
import re
import signal
import stat
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Arch-only runtime; keeps repository imports usable on Windows.
    fcntl = None


ROTATED_NAME = re.compile(r"^.+\.\d{8}T\d{6}Z(?:\.\d+)?$")
MAX_METADATA_BYTES = 32 * 1024 * 1024


def _regular_file(path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Expected a regular file: {path.name}")
    return metadata


def _checkpoint_identity(path, input_path):
    metadata = _regular_file(path)
    if metadata is None:
        return None
    if metadata.st_size > MAX_METADATA_BYTES:
        raise ValueError("Invalid watcher checkpoint")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Invalid watcher checkpoint")
    identity = payload.get("identity")
    if (payload.get("version") not in (1, 2)
            or payload.get("input_path") != str(input_path.resolve())
            or not isinstance(identity, list) or len(identity) != 2
            or any(type(value) is not int or value < 0 for value in identity)):
        raise ValueError("Invalid watcher checkpoint")
    return tuple(identity)


def _destination(path, now):
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = path.with_name(f"{path.name}.{stamp}")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.{stamp}.{suffix}")
        suffix += 1
    return candidate


def _create_active(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    path.chmod(0o600)


def _rotate(path, max_bytes, now):
    metadata = _regular_file(path)
    if metadata is None:
        return None, "missing"
    if metadata.st_size < max_bytes:
        return None, "below_threshold"
    destination = _destination(path, now)
    path.rename(destination)
    try:
        _create_active(path)
    except Exception:
        destination.rename(path)
        raise
    destination.chmod(0o600)
    return destination, "rotated"


def _rollback_rotation(active, rotated):
    metadata = _regular_file(active)
    if metadata is None or metadata.st_size != 0:
        raise RuntimeError("Cannot safely roll back failed Nginx reopen")
    active.unlink()
    rotated.rename(active)


def _nginx_reopen(pid_path):
    metadata = _regular_file(pid_path)
    if metadata is None or metadata.st_size > 32 or metadata.st_uid != os.geteuid():
        raise ValueError("Invalid Nginx PID file")
    raw = pid_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", raw):
        raise ValueError("Invalid Nginx PID file")
    pid = int(raw)
    status_text = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    uid_line = next((line for line in status_text.splitlines() if line.startswith("Uid:")), "")
    real_uid = int(uid_line.split()[1]) if uid_line else -1
    command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0", 1)[0]
    command_text = os.fsdecode(command)
    is_nginx_master = (command_text.startswith("nginx: master process ")
                       or Path(command_text).name == "nginx")
    if real_uid != os.geteuid() or not is_nginx_master:
        raise ValueError("PID file does not identify this user's Nginx master")
    os.kill(pid, signal.SIGUSR1)


def _rotated_files(path):
    prefix = path.name + "."
    candidates = []
    for candidate in path.parent.glob(prefix + "*"):
        metadata = _regular_file(candidate)
        if metadata and ROTATED_NAME.fullmatch(candidate.name):
            candidates.append((candidate, (metadata.st_dev, metadata.st_ino)))
    return sorted(candidates, key=lambda item: item[0].name, reverse=True)


def _prune(path, keep, protected_identity=None):
    removed = []
    for candidate, identity in _rotated_files(path)[keep:]:
        if protected_identity is not None and identity == protected_identity:
            continue
        candidate.unlink()
        removed.append(candidate.name)
    return removed


def rotate_logs(access_path, audit_path, checkpoint_path, nginx_pid_path, max_bytes,
                keep, lock_path=None, now=None, reopen=None):
    if fcntl is None:
        raise OSError("Log rotation requires POSIX file locking")
    if type(max_bytes) is not int or max_bytes <= 0 or type(keep) is not int or keep <= 0:
        raise ValueError("Rotation limits must be positive integers")
    access_path, audit_path = Path(access_path), Path(audit_path)
    checkpoint_path, nginx_pid_path = Path(checkpoint_path), Path(nginx_pid_path)
    lock_path = Path(lock_path) if lock_path else access_path.parent / "logrotate.lock"
    resolved = [path.resolve() for path in (access_path, audit_path, checkpoint_path,
                                             nginx_pid_path, lock_path)]
    if len(resolved) != len(set(resolved)):
        raise ValueError("Log rotation paths must differ")
    access_path.parent.mkdir(parents=True, exist_ok=True)
    lock_flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
                  | getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(lock_path, lock_flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchmod(descriptor, 0o600)
        current = now or datetime.now(timezone.utc)
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise ValueError("Rotation clock must be timezone-aware")
        checkpoint_identity = _checkpoint_identity(checkpoint_path, access_path)
        access_metadata = _regular_file(access_path)
        if access_metadata is None:
            access_result = {"action": "missing"}
        elif access_metadata.st_size < max_bytes:
            access_result = {"action": "below_threshold"}
        elif checkpoint_identity != (access_metadata.st_dev, access_metadata.st_ino):
            access_result = {"action": "watcher_not_on_active_file"}
        else:
            rotated, _ = _rotate(access_path, max_bytes, current)
            try:
                (reopen or _nginx_reopen)(nginx_pid_path)
            except Exception:
                _rollback_rotation(access_path, rotated)
                raise
            access_result = {"action": "rotated", "file": rotated.name}

        rotated_audit, audit_action = _rotate(audit_path, max_bytes, current)
        audit_result = {"action": audit_action}
        if rotated_audit:
            audit_result["file"] = rotated_audit.name
        access_result["removed"] = _prune(access_path, keep, checkpoint_identity)
        audit_result["removed"] = _prune(audit_path, keep)
        return {"access": access_result, "audit": audit_result}
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Rotate bounded PBL4 Arch lab logs")
    parser.add_argument("--access", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--nginx-pid", type=Path, required=True)
    parser.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--keep", type=int, default=8)
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args(argv)
    try:
        report = rotate_logs(args.access, args.audit, args.checkpoint, args.nginx_pid,
                             args.max_bytes, args.keep, args.lock)
    except BlockingIOError:
        print("Log rotation is already running.")
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        print("Cannot rotate logs safely; inspect paths, checkpoint and Nginx service.")
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
