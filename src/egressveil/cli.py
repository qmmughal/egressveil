"""Command-line interface."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final
from urllib.parse import urlsplit

import typer

from egressveil import __version__
from egressveil.config import (
    CONFIG_ENV_VAR,
    EgressVeilConfig,
    LoadResult,
    is_loopback_host,
    load_config,
)

MIN_PYTHON: Final = (3, 11)

app = typer.Typer(
    name="egressveil",
    help="EgressVeil - the local privacy gateway for AI coding agents.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
config_app = typer.Typer(help="Inspect and validate configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")

ConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        help=f"Path to a YAML config file. Defaults to ${CONFIG_ENV_VAR}, "
        "./egressveil.yaml, the user config directory, then built-in defaults.",
        dir_okay=False,
        resolve_path=False,
    ),
]


def _print_source(result: LoadResult) -> None:
    src = result.source
    where = str(src.path) if src.path else "built-in defaults"
    typer.echo(f"Config source: {where} ({src.origin})")


# --------------------------------------------------------------------------- version


@app.command()
def version() -> None:
    """Show the EgressVeil version."""
    typer.echo(f"egressveil {__version__}")


# --------------------------------------------------------------------------- config


@config_app.command("validate")
def config_validate(config: ConfigOption = None) -> None:
    """Validate configuration. Never prints configuration values that could be secret."""
    result = load_config(config)
    _print_source(result)
    for issue in result.issues:
        typer.echo(f"  {issue}", err=issue.level.value == "error")

    if result.config is None:
        typer.echo(f"Configuration is INVALID ({len(result.errors)} error(s)).", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Configuration is valid ({len(result.warnings)} warning(s)).")
    typer.echo("Effective settings:")
    for key, value in result.config.summary():
        typer.echo(f"  {key:<36} {value}")


# --------------------------------------------------------------------------- doctor


class Status(StrEnum):
    OK = "OK"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class Check:
    status: Status
    name: str
    detail: str


def _check_python() -> Check:
    current = sys.version_info[:3]
    text = ".".join(map(str, current))
    if current[:2] >= MIN_PYTHON:
        return Check(Status.OK, "python", f"{text} ({platform.python_implementation()})")
    need = ".".join(map(str, MIN_PYTHON))
    return Check(Status.FAIL, "python", f"{text} found; {need}+ is required")


def _check_platform() -> Check:
    return Check(Status.INFO, "platform", f"{platform.system()} {platform.release()} ({os.name})")


def _check_config(result: LoadResult) -> Check:
    src = str(result.source.path) if result.source.path else "built-in defaults"
    if result.config is None:
        return Check(
            Status.FAIL,
            "config",
            f"{src}: {len(result.errors)} error(s); run 'egressveil config validate'",
        )
    if result.warnings:
        return Check(Status.WARN, "config", f"{src}: valid with {len(result.warnings)} warning(s)")
    return Check(Status.OK, "config", f"{src}: valid")


def _check_port(cfg: EgressVeilConfig) -> Check:
    host, port = cfg.gateway.listen_host, cfg.gateway.listen_port
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError:
        return Check(Status.WARN, "listen port", f"{host}:{port} is in use or not bindable")
    return Check(Status.OK, "listen port", f"{host}:{port} is available")


def _check_audit(cfg: EgressVeilConfig) -> Check:
    if not cfg.audit.enabled:
        return Check(Status.INFO, "audit log", "disabled")
    target = cfg.audit.resolved_path
    probe = target.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if os.access(probe, os.W_OK):
        return Check(Status.OK, "audit log", f"{target} (writable location)")
    return Check(Status.WARN, "audit log", f"{target}: directory is not writable")


def _check_proxy_env() -> Check:
    names = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
    found = sorted({n for n in names for k in (n, n.lower()) if os.environ.get(k)})
    if not found:
        return Check(Status.INFO, "proxy env", "no HTTP(S)_PROXY/ALL_PROXY variables set")
    # Values are hidden: proxy URLs frequently embed credentials.
    return Check(Status.INFO, "proxy env", f"set: {', '.join(found)} (values hidden)")


def _base_url_state(var: str, cfg: EgressVeilConfig) -> str:
    value = os.environ.get(var)
    if not value:
        return f"{var} not set"
    parts = urlsplit(value)
    host = parts.hostname or ""
    if is_loopback_host(host):
        try:
            port = parts.port
        except ValueError:
            port = None
        if port == cfg.gateway.listen_port:
            return f"{var} points at the EgressVeil listen address"
        return f"{var} points at a local address on a different port"
    return f"{var} points at a non-local endpoint (value hidden)"


def _check_tool(name: str, label: str, extra: str) -> Check:
    path = shutil.which(name)
    if path:
        return Check(Status.OK, label, f"'{name}' found on PATH; {extra}")
    return Check(Status.INFO, label, f"'{name}' not found on PATH; {extra}")


def _integration_checks(cfg: EgressVeilConfig) -> list[Check]:
    return [
        _check_tool("claude", "claude code", _base_url_state("ANTHROPIC_BASE_URL", cfg)),
        _check_tool(
            "aider",
            "aider",
            "; ".join(
                _base_url_state(v, cfg)
                for v in ("ANTHROPIC_BASE_URL", "OPENAI_API_BASE", "OPENAI_BASE_URL")
            ),
        ),
        _check_tool(
            "cursor", "cursor", "experimental: most traffic is not routable to a local gateway"
        ),
        Check(Status.INFO, "openclaw", "integration planned; not yet supported"),
    ]


def run_doctor(config_path: Path | None) -> list[Check]:
    checks: list[Check] = [_check_python(), _check_platform()]
    result = load_config(config_path)
    checks.append(_check_config(result))
    cfg = result.config
    if cfg is not None:
        steps: list[Callable[[EgressVeilConfig], Check]] = [_check_port, _check_audit]
        checks.extend(step(cfg) for step in steps)
        checks.append(_check_proxy_env())
        checks.extend(_integration_checks(cfg))
    checks.append(
        Check(Status.INFO, "gateway", "proxy not implemented in this release (Phase 0 scaffold)"),
    )
    return checks


@app.command()
def doctor(config: ConfigOption = None) -> None:
    """Check Python, configuration, local environment and integration prerequisites."""
    typer.echo(f"egressveil {__version__} doctor")
    checks = run_doctor(config)
    width = max(len(c.name) for c in checks)
    for c in checks:
        typer.echo(f"  [{c.status.value:<4}] {c.name:<{width}}  {c.detail}")
    failures = sum(c.status is Status.FAIL for c in checks)
    warnings = sum(c.status is Status.WARN for c in checks)
    typer.echo(f"{failures} failure(s), {warnings} warning(s).")
    if failures:
        raise typer.Exit(code=1)


def main() -> None:
    """Console-script entry point."""
    app()
