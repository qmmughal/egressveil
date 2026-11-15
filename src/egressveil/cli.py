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
        if _gateway_health(cfg) is not None:
            return Check(
                Status.OK, "listen port", f"EgressVeil gateway is running on {host}:{port}"
            )
        return Check(Status.WARN, "listen port", f"{host}:{port} is in use or not bindable")
    return Check(Status.OK, "listen port", f"{host}:{port} is available (gateway not running)")


def _gateway_health(cfg: EgressVeilConfig) -> dict[str, object] | None:
    """Return the running gateway's health document, or ``None``."""
    import json
    import urllib.request

    from egressveil.proxy.server import HEALTH_PATH

    host = cfg.gateway.listen_host
    netloc = f"[{host}]" if ":" in host else host
    url = f"http://{netloc}:{cfg.gateway.listen_port}{HEALTH_PATH}"
    # Explicitly bypass any HTTP(S)_PROXY settings: this is a loopback probe.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=1.5) as resp:
            doc = json.loads(resp.read(4096))
    except (OSError, ValueError):
        return None
    if isinstance(doc, dict) and doc.get("service") == "egressveil":
        return doc
    return None


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
        checks.extend(_detector_checks(cfg))
    return checks


def _detector_checks(cfg: EgressVeilConfig) -> list[Check]:
    from egressveil.detectors import IMPLEMENTED_CATEGORIES

    checks: list[Check] = []
    active = sorted(
        n for n, d in cfg.detectors.items() if d.enabled and n in IMPLEMENTED_CATEGORIES
    )
    checks.append(
        Check(
            Status.OK if active else Status.WARN,
            "detectors",
            f"active: {', '.join(active) or 'none'}",
        )
    )
    pending = sorted(
        n for n, d in cfg.detectors.items() if d.enabled and n not in IMPLEMENTED_CATEGORIES
    )
    if pending:
        checks.append(
            Check(
                Status.INFO, "detectors", f"enabled but not implemented yet: {', '.join(pending)}"
            )
        )
    if cfg.providers["openai"].enabled:
        checks.append(
            Check(
                Status.WARN, "providers", "openai is enabled but not supported by the gateway yet"
            )
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


# --------------------------------------------------------------------------- serve


def _load_or_exit(config: Path | None) -> EgressVeilConfig:
    result = load_config(config)
    if result.config is None:
        _print_source(result)
        for issue in result.errors:
            typer.echo(f"  {issue}", err=True)
        typer.echo("Configuration is INVALID; run 'egressveil config validate'.", err=True)
        raise typer.Exit(code=1)
    return result.config


def _base_url_instructions(url: str) -> list[str]:
    if os.name == "nt":
        return [
            f'  PowerShell:  $env:ANTHROPIC_BASE_URL = "{url}"',
            f"  cmd.exe:     set ANTHROPIC_BASE_URL={url}",
        ]
    return [f"  export ANTHROPIC_BASE_URL={url}"]


@app.command()
def serve(config: ConfigOption = None) -> None:
    """Run the local gateway for the Anthropic API (Claude Code)."""
    from aiohttp import web

    from egressveil.proxy import build_components, create_app

    cfg = _load_or_exit(config)
    try:
        components = build_components(cfg)
    except (OSError, ValueError) as exc:
        typer.echo(f"egressveil: cannot start: {exc}", err=True)
        raise typer.Exit(code=1) from None

    g = cfg.gateway
    netloc = f"[{g.listen_host}]" if ":" in g.listen_host else g.listen_host
    base_url = f"http://{netloc}:{g.listen_port}"
    lines = [
        f"EgressVeil {__version__} gateway",
        f"  listening   {base_url}",
        f"  upstream    {components.provider.upstream_origin}",
        f"  mode        {g.mode.value}",
        f"  audit log   {components.audit.path or 'disabled'}",
    ]
    for issue in load_config(config).warnings:
        lines.append(f"  {issue}")
    pending = sorted(
        n for n, d in cfg.detectors.items() if d.enabled and n not in _implemented_categories()
    )
    if pending:
        lines.append(f"  note: not implemented yet, no effect: {', '.join(pending)}")
    if cfg.providers["openai"].enabled:
        lines.append("  note: openai provider is not supported by the gateway yet; ignored")
    lines += [
        "",
        "Point Claude Code at the gateway:",
        *_base_url_instructions(base_url),
        "",
        "Press Ctrl+C to stop.",
    ]
    typer.echo("\n".join(lines))

    try:
        web.run_app(
            create_app(components),
            host=g.listen_host,
            port=g.listen_port,
            print=None,
            access_log=None,  # access logs would include query strings
            handle_signals=True,
        )
    except OSError as exc:
        typer.echo(f"egressveil: cannot listen on {base_url}: {exc.strerror}", err=True)
        raise typer.Exit(code=1) from None


def _implemented_categories() -> frozenset[str]:
    from egressveil.detectors import IMPLEMENTED_CATEGORIES

    return IMPLEMENTED_CATEGORIES


# --------------------------------------------------------------------------- scan


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, col


@app.command()
def scan(
    paths: Annotated[
        list[str],
        typer.Argument(help="Files to scan. Use '-' to read standard input."),
    ],
    config: ConfigOption = None,
) -> None:
    """Scan files with the configured detectors and policy. Never prints matched values.

    Exit status: 0 = nothing found, 1 = findings, 2 = a file could not be read.
    """
    import secrets as _secrets

    from egressveil.audit import AuditLogger
    from egressveil.detectors import IMPLEMENTED_CATEGORIES, build_detectors
    from egressveil.inspection import Inspector
    from egressveil.policy import PolicyAction
    from egressveil.policy.engine import PolicyEngine
    from egressveil.redactor import Redactor

    cfg = _load_or_exit(config)
    key = _secrets.token_bytes(32)
    enabled = [n for n, d in cfg.detectors.items() if d.enabled and n in IMPLEMENTED_CATEGORIES]
    inspector = Inspector(
        detectors=build_detectors(enabled),
        engine=PolicyEngine(cfg.policy),
        redactor=Redactor(key),
        audit=AuditLogger(None, key),
        mode=cfg.gateway.mode,
        allow_opaque_content=cfg.gateway.allow_opaque_content,
    )
    limit = cfg.gateway.max_request_body_bytes
    total = 0
    unreadable = 0
    for name in paths:
        try:
            if name == "-":
                data = sys.stdin.buffer.read(limit + 1)
            else:
                with Path(name).open("rb") as fh:
                    data = fh.read(limit + 1)
        except OSError as exc:
            typer.echo(f"{name}: cannot read: {exc.strerror}", err=True)
            unreadable += 1
            continue
        if len(data) > limit:
            typer.echo(f"{name}: skipped, larger than {limit} bytes", err=True)
            unreadable += 1
            continue
        text = data.decode("utf-8", errors="replace")
        findings = sorted(inspector.scan_text(text), key=lambda f: (f.start, f.rule_id))
        for f in findings:
            action = inspector.action_for(f)
            if action is PolicyAction.ALLOW:
                continue
            line, col = _line_col(text, f.start)
            typer.echo(f"{name}:{line}:{col}: {action.value:<8} {f.detector}/{f.rule_id}")
            total += 1
    typer.echo(f"{total} finding(s).")
    if unreadable:
        raise typer.Exit(code=2)
    if total:
        raise typer.Exit(code=1)


def main() -> None:
    """Console-script entry point."""
    app()
