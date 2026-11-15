from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from egressveil.audit import AuditLogger, load_or_create_key
from tests import fakes


def test_key_created_once_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "state" / "egressveil.key"
    key = load_or_create_key(path)
    assert len(key) == 32
    assert load_or_create_key(path) == key


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_key_and_log_are_user_only(tmp_path: Path) -> None:
    key_path = tmp_path / "s" / "egressveil.key"
    key = load_or_create_key(key_path)
    log_path = tmp_path / "s" / "audit.jsonl"
    AuditLogger(log_path, key).write({"x": 1})
    for p in (key_path, log_path):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700


def test_corrupt_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "egressveil.key"
    path.write_text("not-hex", encoding="ascii")
    with pytest.raises(ValueError, match="corrupt"):
        load_or_create_key(path)
    path.write_text("abcd", encoding="ascii")
    with pytest.raises(ValueError, match="too short"):
        load_or_create_key(path)


def test_events_are_jsonl_with_timestamp(tmp_path: Path) -> None:
    log = AuditLogger(tmp_path / "audit.jsonl", b"k" * 32)
    log.write({"request_id": "ev_1"})
    log.write({"request_id": "ev_2"})
    lines = (tmp_path / "audit.jsonl").read_text(encoding="ascii").splitlines()
    events = [json.loads(line) for line in lines]
    assert [e["request_id"] for e in events] == ["ev_1", "ev_2"]
    assert all("ts" in e for e in events)


def test_digest_is_keyed_and_hides_value() -> None:
    value = fakes.github_token()
    a = AuditLogger(None, b"a" * 32).digest(value)
    b = AuditLogger(None, b"b" * 32).digest(value)
    assert a != b
    assert len(a) == 16
    assert value not in a


def test_disabled_logger_writes_nothing(tmp_path: Path) -> None:
    log = AuditLogger(None, b"k" * 32)
    log.write({"x": 1})
    assert log.path is None
    assert list(tmp_path.rglob("*.jsonl")) == []
