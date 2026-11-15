from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

from typer.testing import CliRunner

from egressveil.cli import app, run_doctor
from tests import fakes
from tests.test_gateway import free_port

runner = CliRunner()


def test_scan_reports_location_and_rule_but_not_value(tmp_path: Path) -> None:
    secret = fakes.github_token()
    target = tmp_path / "notes.txt"
    target.write_text(f"line one\nclone with {secret}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == 1, result.output
    assert f"{target}:2:12: BLOCK" in result.output
    assert "secrets/github_token" in result.output
    assert secret not in result.output
    assert "1 finding(s)." in result.output


def test_scan_clean_file_and_stdin(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(clean)]).exit_code == 0

    result = runner.invoke(app, ["scan", "-"], input=f"token {fakes.jwt()}\n")
    assert result.exit_code == 1
    assert "<stdin>" not in result.output
    assert "-:1:7: BLOCK" in result.output


def test_scan_respects_policy(write_config: Callable[[str], Path], tmp_path: Path) -> None:
    cfg = write_config("policy:\n  rules:\n    - detector: secrets\n      action: ALLOW\n")
    target = tmp_path / "f.txt"
    target.write_text(fakes.github_token(), encoding="utf-8")
    result = runner.invoke(app, ["scan", "-c", str(cfg), str(target)])
    assert result.exit_code == 0
    assert "0 finding(s)." in result.output


def test_scan_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "nope.txt")])
    assert result.exit_code == 2


def test_serve_refuses_invalid_config(write_config: Callable[[str], Path]) -> None:
    cfg = write_config("telemetry:\n  enabled: true\n")
    result = runner.invoke(app, ["serve", "-c", str(cfg)])
    assert result.exit_code == 1
    assert "INVALID" in result.output


def test_doctor_lists_active_detectors() -> None:
    checks = run_doctor(None)
    details = [c.detail for c in checks if c.name == "detectors"]
    assert "active: secrets, tokens" in details
    assert any("pii" in d and "not implemented" in d for d in details)


def test_serve_process_starts_and_answers_health(tmp_path: Path) -> None:
    """Real `egressveil serve` process: starts, reports healthy, doctor sees it."""
    port = free_port()
    cfg = tmp_path / "egressveil.yaml"
    audit = (tmp_path / "audit.jsonl").as_posix()
    cfg.write_text(
        f"gateway:\n  listen_port: {port}\naudit:\n  path: '{audit}'\n", encoding="utf-8"
    )
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "egressveil", "serve", "--config", str(cfg)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        doc = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and doc is None:
            try:
                with opener.open(f"http://127.0.0.1:{port}/_egressveil/health", timeout=1) as r:
                    doc = json.loads(r.read())
            except OSError:
                time.sleep(0.2)
        assert doc is not None, "gateway did not become healthy"
        assert doc["status"] == "ok"

        port_check = next(c for c in run_doctor(cfg) if c.name == "listen port")
        assert "gateway is running" in port_check.detail
    finally:
        proc.terminate()
        out, _ = proc.communicate(timeout=30)
    banner = out.decode(errors="replace")
    assert f"http://127.0.0.1:{port}" in banner
    assert "ANTHROPIC_BASE_URL" in banner
