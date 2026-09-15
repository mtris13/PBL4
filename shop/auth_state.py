"""Persistent login throttling and revocable browser sessions for one SQLite app."""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone


def timestamp(now):
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("Authentication clock must return a timezone-aware datetime")
    return int(now.astimezone(timezone.utc).timestamp())


def digest(secret, purpose, value):
    if not isinstance(value, str):
        raise ValueError("Authentication state value must be text")
    key = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    message = purpose.encode("ascii") + b"\0" + value.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def throttle_key(secret, email):
    return digest(secret, "login-throttle-v1", email)


def throttle_remaining(db, identity_hash, now):
    current = timestamp(now)
    row = db.execute("SELECT blocked_until FROM login_throttle WHERE identity_hash=?",
                     (identity_hash,)).fetchone()
    return max(0, row["blocked_until"] - current) if row else 0


def record_failure(db, identity_hash, now, limit, window_seconds, block_seconds, max_entries):
    current = timestamp(now)
    cutoff = current - max(window_seconds, block_seconds)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM login_throttle WHERE updated_at<=? AND blocked_until<=?",
                   (cutoff, current))
        row = db.execute(
            "SELECT failures, window_started, blocked_until FROM login_throttle WHERE identity_hash=?",
            (identity_hash,),
        ).fetchone()
        if row and row["blocked_until"] > current:
            remaining = row["blocked_until"] - current
            db.commit()
            return remaining
        if row and current - row["window_started"] < window_seconds:
            failures, started = row["failures"] + 1, row["window_started"]
        else:
            failures, started = 1, current
        blocked_until = current + block_seconds if failures >= limit else 0
        if row is None:
            count = db.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0]
            if count >= max_entries:
                db.commit()
                return block_seconds
        db.execute(
            "INSERT INTO login_throttle VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(identity_hash) DO UPDATE SET failures=excluded.failures, "
            "window_started=excluded.window_started, blocked_until=excluded.blocked_until, "
            "updated_at=excluded.updated_at",
            (identity_hash, failures, started, blocked_until, current),
        )
        db.commit()
        return max(0, blocked_until - current)
    except Exception:
        db.rollback()
        raise


def create_browser_session(db, secret, user_id, now, lifetime_seconds, max_sessions,
                           replaced_token=None, cleared_throttle=None):
    current = timestamp(now)
    raw_token = secrets.token_urlsafe(32)
    token_hash = digest(secret, "browser-session-v1", raw_token)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM browser_sessions WHERE expires_at<=?", (current,))
        if replaced_token:
            old_hash = digest(secret, "browser-session-v1", replaced_token)
            db.execute("DELETE FROM browser_sessions WHERE token_hash=?", (old_hash,))
        if cleared_throttle:
            db.execute("DELETE FROM login_throttle WHERE identity_hash=?", (cleared_throttle,))
        db.execute("INSERT INTO browser_sessions VALUES (?, ?, ?, ?)",
                   (token_hash, user_id, current, current + lifetime_seconds))
        count = db.execute("SELECT COUNT(*) FROM browser_sessions WHERE user_id=?",
                           (user_id,)).fetchone()[0]
        stale = db.execute(
            "SELECT token_hash FROM browser_sessions WHERE user_id=? AND token_hash<>? "
            "ORDER BY created_at ASC, token_hash ASC LIMIT ?",
            (user_id, token_hash, max(0, count - max_sessions)),
        ).fetchall()
        if stale:
            db.executemany("DELETE FROM browser_sessions WHERE token_hash=?",
                           ((row["token_hash"],) for row in stale))
        db.commit()
        return raw_token
    except Exception:
        db.rollback()
        raise


def authenticated_user(db, secret, user_id, raw_token, now):
    if type(user_id) is not int or not isinstance(raw_token, str) or not 20 <= len(raw_token) <= 128:
        return None
    current = timestamp(now)
    token_hash = digest(secret, "browser-session-v1", raw_token)
    row = db.execute(
        "SELECT u.id, u.name, u.email FROM browser_sessions s "
        "JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND s.user_id=? AND s.expires_at>?",
        (token_hash, user_id, current),
    ).fetchone()
    if row is None:
        db.execute("DELETE FROM browser_sessions WHERE token_hash=?", (token_hash,))
        db.commit()
    return row


def revoke_browser_session(db, secret, raw_token):
    if not isinstance(raw_token, str) or not raw_token:
        return
    token_hash = digest(secret, "browser-session-v1", raw_token)
    db.execute("DELETE FROM browser_sessions WHERE token_hash=?", (token_hash,))
    db.commit()
