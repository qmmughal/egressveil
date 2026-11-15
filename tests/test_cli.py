from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from egressveil import __version__
from egressveil.cli import Status, app, run_doctor
from tests.conftest import FAKE_CREDENTIAL

runner = CliRunner()


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("version", "config", "doctor"):
        assert command in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"egressveil {__version__}"


def test_config_help() -> None:
    result = runner.invoke(app, ["config", "--help"])
    assert result.exit_code == 0
    assert "validate" in result.output


def test_config_validate_defaults() -> None:
    result = runner.invoke(app, ["config", "validate"])
    assert result.exit_code == 0, result.output
    assert "built-in defaults" in result.output
    assert "Configuration is valid" in result.output
    assert "127.0.0.1:8787" in result.output


def test_config_validate_example(example_config_path: Path) -> None:
    result = runner.invoke(app, ["config", "validate", "--config", str(example_config_path)])
    assert result.exit_code == 0, result.output
    assert "Configuration is valid" in result.output


def test_config_validate_invalid(write_config: Callable[[str], Path]) -> None:
    path = write_config("gateway:\n  listen_host: 0.0.0.0\n")
    result = runner.invoke(app, ["config", "validate", "-c", str(path)])
    assert result.exit_code == 1
    assert "INVALID" in result.output
    assert "gateway.listen_host" in result.output


def test_config_validate_never_prints_secrets(write_config: Callable[[str], Path]) -> None:
    path = write_config(
        f"detectors:\n  internal_hostnames:\n    internal_domains: ['{FAKE_CREDENTIAL}']\n"
    )
    result = runner.invoke(app, ["config", "validate", "-c", str(path)])
    assert result.exit_code == 1
    assert FAKE_CREDENTIAL not in result.output
    assert "looks like a credential" in result.output


def test_config_validate_hides_upstream_path(write_config: Callable[[str], Path]) -> None:
    path = write_config(
        "providers:\n  anthropic:\n    upstream_url: https://api.anthropic.com/private-path\n"
    )
    result = runner.invoke(app, ["config", "validate", "-c", str(path)])
    assert result.exit_code == 0, result.output
    assert "private-path" not in result.output


def test_doctor_passes_with_defaults() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "python" in result.output
    assert "0 failure(s)" in result.output


def test_doctor_fails_on_invalid_config(write_config: Callable[[str], Path]) -> None:
    path = write_config("telemetry:\n  enabled: true\n")
    result = runner.invoke(app, ["doctor", "--config", str(path)])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_doctor_hides_base_url_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://remote.example.net/secret-route")
    monkeypatch.setenv("HTTPS_PROXY", "http://user:hunter2@proxy.example.net:3128")
    result = runner.invoke(app, ["doctor"])
    assert "secret-route" not in result.output
    assert "hunter2" not in result.output
    assert "non-local endpoint" in result.output


def test_doctor_detects_local_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:8787")
    checks = run_doctor(None)
    claude = next(c for c in checks if c.name == "claude code")
    assert "points at the EgressVeil listen address" in claude.detail


def test_doctor_reports_core_checks() -> None:
    names = {c.name for c in run_doctor(None)}
    assert {"python", "config", "listen port", "audit log", "claude code", "aider"} <= names
    assert all(c.status is not Status.FAIL for c in run_doctor(None))


def test_module_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "egressveil", "version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert __version__ in proc.stdout
