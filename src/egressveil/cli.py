"""Command-line interface."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer

from egressveil import __version__
from egressveil.config import CONFIG_ENV_VAR, EgressVeilConfig, LoadResult, load_config
from egressveil.doctor import OPENAI_MOUNT_PATH, Check, Status, gateway_base_url, run_doctor

__all__ = ["Check", "Status", "app", "main", "run_doctor"]

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


def _load_or_exit(config: Path | None) -> LoadResult:
    result = load_config(config)
    if result.config is None:
        _print_source(result)
        for issue in result.errors:
            typer.echo(f"  {issue}", err=True)
        typer.echo("Configuration is INVALID; run 'egressveil config validate'.", err=True)
        raise typer.Exit(code=1)
    return result


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


@app.command()
def doctor(config: ConfigOption = None) -> None:
    """Check Python, configuration, gateway, routing and integration prerequisites."""
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


def _routing_instructions(cfg: EgressVeilConfig) -> list[str]:
    base = gateway_base_url(cfg)
    pairs: list[tuple[str, str]] = []
    if cfg.providers["anthropic"].enabled:
        pairs.append(("ANTHROPIC_BASE_URL", base))
    if cfg.providers["openai"].enabled:
        pairs.append(("OPENAI_BASE_URL", base + OPENAI_MOUNT_PATH))
    if os.name == "nt":
        return [f'  PowerShell:  $env:{k} = "{v}"' for k, v in pairs]
    return [f"  export {k}={v}" for k, v in pairs]


@app.command()
def serve(config: ConfigOption = None) -> None:
    """Run the local gateway (Anthropic API at /, OpenAI-compatible API at /openai)."""
    from aiohttp import web

    from egressveil.proxy import build_components, create_app

    result = _load_or_exit(config)
    cfg = result.config
    assert cfg is not None  # noqa: S101 - guaranteed by _load_or_exit
    try:
        components = build_components(cfg)
    except (OSError, ValueError) as exc:
        typer.echo(f"egressveil: cannot start: {exc}", err=True)
        raise typer.Exit(code=1) from None

    g = cfg.gateway
    base_url = gateway_base_url(cfg)
    lines = [f"EgressVeil {__version__} gateway", f"  listening   {base_url}"]
    for name, provider in sorted(components.providers.items()):
        mount = "/openai" if name == "openai" else "/"
        lines.append(f"  {name:<11} {mount:<8} -> {provider.upstream_origin}")
    lines += [
        f"  mode        {g.mode.value}",
        f"  detectors   {', '.join(sorted(n for n, d in cfg.detectors.items() if d.enabled))}",
        f"  audit log   {components.audit.path or 'disabled'}",
    ]
    lines += [f"  {issue}" for issue in result.warnings]
    lines += ["", "Point your agent at the gateway (or use 'egressveil run -- <agent>'):"]
    lines += _routing_instructions(cfg)
    lines += ["", "Press Ctrl+C to stop."]
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


# --------------------------------------------------------------------------- run


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Run an AI coding agent with its API traffic routed through EgressVeil.\n\n"
    "Example: egressveil run -- claude",
)
def run(
    ctx: typer.Context,
    config: ConfigOption = None,
    start: Annotated[
        bool,
        typer.Option("--start/--no-start", help="Start the gateway if it is not running."),
    ] = True,
) -> None:
    from egressveil.launcher import LaunchError, run_agent

    result = _load_or_exit(config)
    assert result.config is not None  # noqa: S101
    try:
        code = run_agent(
            list(ctx.args), result.config, config or result.source.path, start_gateway=start
        )
    except LaunchError as exc:
        typer.echo(f"egressveil: {exc}", err=True)
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=code)


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
    from egressveil.audit import KEY_FILENAME, AuditLogger, load_or_create_key
    from egressveil.inspection import Inspector
    from egressveil.redactor import Redactor

    cfg = _load_or_exit(config).config
    assert cfg is not None  # noqa: S101
    # Use the gateway's digest key so digests match the audit log and can be
    # copied into policy.allow; fall back to a throwaway key.
    try:
        key = (
            load_or_create_key(cfg.audit.resolved_path.parent / KEY_FILENAME)
            if cfg.audit.enabled
            else secrets.token_bytes(32)
        )
    except (OSError, ValueError):
        key = secrets.token_bytes(32)
    inspector = Inspector.from_config(cfg, redactor=Redactor(key), audit=AuditLogger(None, key))
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
        findings = sorted(inspector.evaluate_text(text), key=lambda t: (t[0].start, t[0].rule_id))
        for f, action, digest in findings:
            line, col = _line_col(text, f.start)
            typer.echo(
                f"{name}:{line}:{col}: {action.value:<8} {f.detector}/{f.rule_id}  digest={digest}"
            )
            total += 1
    typer.echo(f"{total} finding(s).")
    if unreadable:
        raise typer.Exit(code=2)
    if total:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- setup

_AGENTS = ("claude-code", "aider", "openclaw", "cursor")


@app.command()
def setup(
    agent: Annotated[str, typer.Argument(help=f"One of: {', '.join(_AGENTS)}.")],
    config: ConfigOption = None,
) -> None:
    """Show how to route a specific agent through EgressVeil."""
    from egressveil.doctor import openclaw_config_path

    cfg = _load_or_exit(config).config
    assert cfg is not None  # noqa: S101
    agent = agent.lower()
    base = gateway_base_url(cfg)
    openai_on = cfg.providers["openai"].enabled
    if agent == "claude-code":
        lines = [
            "Claude Code reads ANTHROPIC_BASE_URL.",
            "",
            "  egressveil run -- claude",
            "",
            "or start 'egressveil serve' and set:",
            *_routing_instructions(cfg),
        ]
    elif agent == "aider":
        lines = [
            "Aider (LiteLLM) reads ANTHROPIC_BASE_URL and OPENAI_API_BASE.",
            "",
            "  egressveil run -- aider --model anthropic/<model>",
        ]
        if openai_on:
            lines.append("  egressveil run -- aider --model openai/<model>")
        else:
            lines += ["", "For OpenAI models, first set providers.openai.enabled: true."]
    elif agent == "openclaw":
        lines = [
            f"Merge this into {openclaw_config_path()} (JSON5), then restart the OpenClaw gateway",
            "(openclaw gateway restart). Keep your existing apiKey settings.",
            "",
            "{",
            "  models: {",
            "    providers: {",
            "      // Built-in Anthropic provider, routed through EgressVeil",
            f'      anthropic: {{ baseUrl: "{base}" }},',
        ]
        if openai_on:
            lines += [
                "      // OpenAI-compatible provider, routed through EgressVeil",
                "      // (add your usual apiKey and models list)",
                f'      "egressveil-openai": {{ baseUrl: "{base}{OPENAI_MOUNT_PATH}",'
                ' api: "openai-completions" },',
            ]
        lines += [
            "    },",
            "  },",
            "}",
            "",
            "Then check with: egressveil doctor   (looks for the gateway URL in the file)",
        ]
    elif agent == "cursor":
        lines = [
            "Cursor is NOT supported, and EgressVeil cannot protect it.",
            "",
            "Cursor sends model requests from Cursor's own servers, including when you use",
            "'Override OpenAI Base URL', so a gateway on 127.0.0.1 is unreachable for it.",
            "Exposing EgressVeil to the internet to work around this would defeat its purpose,",
            "and the prompt would still pass through Cursor's backend. See docs/integrations.md.",
        ]
    else:
        typer.echo(
            f"egressveil: unknown agent {agent!r}; choose one of: {', '.join(_AGENTS)}", err=True
        )
        raise typer.Exit(code=2)
    typer.echo("\n".join(lines))


def main() -> None:
    """Console-script entry point."""
    app()
