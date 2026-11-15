"""Audit logging.

Writes one JSON object per line. Events contain request metadata, decisions,
detector/rule IDs, JSON locations and keyed digests of matched values. They
never contain request bodies, headers, credentials or raw matched values.

The digest key is a random 32-byte key stored next to the audit log with
user-only permissions (on POSIX; on Windows the file inherits the ACL of the
user's profile directory). Digests let you see that the *same* value occurred
again without storing it.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

__all__ = ["AUDIT_SCHEMA_VERSION", "KEY_FILENAME", "AuditLogger", "load_or_create_key"]

KEY_FILENAME: Final = "egressveil.key"
AUDIT_SCHEMA_VERSION: Final = 1
"""Version of the audit event format (docs/audit-log.md). Bumped only on breaking changes."""
_KEY_BYTES: Final = 32


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def load_or_create_key(path: Path) -> bytes:
    """Read the hex key at ``path`` or create it atomically with mode 0600."""
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        _ensure_private_dir(path.parent)
        key = secrets.token_bytes(_KEY_BYTES)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # lost a race with another process
            return load_or_create_key(path)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key.hex())
        return key
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise ValueError(f"key file {path} is corrupt") from None
    if len(key) < 16:
        raise ValueError(f"key file {path} is too short")
    return key


class AuditLogger:
    """Append-only JSONL audit log. ``path=None`` disables writing."""

    def __init__(self, path: Path | None, key: bytes) -> None:
        self._path = path
        self._key = key
        self._lock = threading.Lock()
        if path is not None:
            _ensure_private_dir(path.parent)
            # Create (or verify we can open) the file up front so the gateway
            # fails at startup, not on the first request.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)

    @property
    def path(self) -> Path | None:
        return self._path

    def digest(self, value: str) -> str:
        """Keyed, truncated digest of a sensitive value, safe to log."""
        mac = hmac.new(
            self._key, b"audit\x00" + value.encode("utf-8", "surrogatepass"), hashlib.sha256
        )
        return mac.hexdigest()[:16]

    def write(self, event: Mapping[str, Any]) -> None:
        if self._path is None:
            return
        record = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            **event,
        }
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        try:
            with self._lock:
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="ascii") as fh:
                    fh.write(line)
        except OSError as exc:
            # Never let audit I/O take down request handling; report on stderr.
            with contextlib.suppress(Exception):
                print(f"egressveil: audit write failed: {exc.strerror}", file=sys.stderr)
