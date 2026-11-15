"""``egressveil doctor``: environment and routing checks.

Every check is careful never to print environment values (base URLs, proxy
URLs) because they can embed credentials.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from egressveil.config import EgressVeilConfig, LoadResult, is_loopback_host, load_config
from egressveil.policy import PolicyAction

__all__ = [
    "Check",
    "Status",
    "gateway_base_url",
    "gateway_health",
    "run_doctor",
]

MIN_PYTHON: Final = (3, 11)
HEALTH_PATH: Final = "/_egressveil/health"
OPENAI_MOUNT_PATH: Final = "/openai/v1"


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


def gateway_base_url(cfg: EgressVeilConfig) -> str:
    """URL agents should use to reach the gateway (always a loopback address)."""
    host = cfg.gateway.listen_host
    if host in {"0.0.0.0", "::"}:  # noqa: S104 - mapping a wildcard bind to loopback
        host = "127.0.0.1"
    netloc = f"[{host}]" if ":" in host else host
    return f"http://{netloc}:{cfg.gateway.listen_port}"


def _opener() -> urllib.request.OpenerDirector:
    # Loopback probes must never go through HTTP(S)_PROXY.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def gateway_health(cfg: EgressVeilConfig) -> dict[str, object] | None:
    """Return the running gateway's health document, or ``None``."""
    try:
        with _opener().open(gateway_base_url(cfg) + HEALTH_PATH, timeout=1.5) as resp:
            doc = json.loads(resp.read(4096))
    except (OSError, ValueError):
        return None
    if isinstance(doc, dict) and doc.get("service") == "egressveil":
        return doc
    return None


# --------------------------------------------------------------------------- checks


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


def _port_in_use(cfg: EgressVeilConfig) -> bool:
    host, port = cfg.gateway.listen_host, cfg.gateway.listen_port
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError:
        return True
    return False


def _check_port(cfg: EgressVeilConfig, running: bool) -> Check:
    host, port = cfg.gateway.listen_host, cfg.gateway.listen_port
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError:
        if running:
            return Check(
                Status.OK, "listen port", f"EgressVeil gateway is running on {host}:{port}"
            )
        return Check(Status.WARN, "listen port", f"{host}:{port} is in use or not bindable")
    return Check(Status.OK, "listen port", f"{host}:{port} is available (gateway not running)")


def _self_test(cfg: EgressVeilConfig, running: bool) -> Check:
    """Send a canary credential to the running gateway and expect a local block.

    The canary is random, shaped like a GitHub token, and generated per run.
    It is only sent when policy BLOCKs secrets, so it never leaves the machine.
    """
    if not running:
        return Check(Status.INFO, "self-test", "skipped: gateway not running")
    actions = {r.detector: r.action for r in cfg.policy.rules}
    if (
        not cfg.detectors["secrets"].enabled
        or actions.get("secrets", cfg.policy.default_action) is not PolicyAction.BLOCK
        or not cfg.providers["anthropic"].enabled
    ):
        return Check(Status.INFO, "self-test", "skipped: needs anthropic + secrets policy BLOCK")
    canary = "gh" + "p_" + secrets.token_hex(18)
    body = json.dumps(
        {
            "model": "egressveil-self-test",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": f"canary {canary}"}],
        }
    ).encode()
    req = urllib.request.Request(  # noqa: S310 - fixed loopback http URL
        gateway_base_url(cfg) + "/v1/messages",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _opener().open(req, timeout=5) as resp:
            decision = resp.headers.get("x-egressveil-decision")
            status = resp.status
    except urllib.error.HTTPError as exc:
        decision = exc.headers.get("x-egressveil-decision")
        status = exc.code
    except OSError:
        return Check(Status.FAIL, "self-test", "could not reach the gateway")
    if status == 400 and decision == "block":
        return Check(Status.OK, "self-test", "canary credential was blocked locally")
    return Check(Status.FAIL, "self-test", f"canary was not blocked (status {status})")


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


def _check_proxy_env(cfg: EgressVeilConfig) -> Check:
    names = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
    found = sorted({n for n in names for k in (n, n.lower()) if os.environ.get(k)})
    mode = cfg.gateway.upstream_proxy
    upstream = {"none": "direct", "env": "via HTTPS_PROXY"}.get(mode, "via configured proxy")
    env_text = f"set: {', '.join(found)} (values hidden)" if found else "no proxy variables set"
    status = Status.WARN if mode == "env" and not found else Status.INFO
    return Check(status, "proxy", f"upstream connection {upstream}; {env_text}")


def _base_url_state(var: str, cfg: EgressVeilConfig, expected_path: str = "") -> str:
    value = os.environ.get(var)
    if not value:
        return f"{var} not set"
    parts = urlsplit(value)
    if not is_loopback_host(parts.hostname or ""):
        return f"{var} points at a non-local endpoint (value hidden)"
    try:
        port = parts.port
    except ValueError:
        port = None
    if port != cfg.gateway.listen_port:
        return f"{var} points at a local address on a different port"
    if expected_path and parts.path.rstrip("/") != expected_path:
        return f"{var} points at the gateway but its path should be {expected_path}"
    return f"{var} points at the EgressVeil gateway"


def _check_tool(names: tuple[str, ...], label: str, extra: str) -> Check:
    for name in names:
        if shutil.which(name):
            return Check(Status.OK, label, f"'{name}' found on PATH; {extra}")
    return Check(Status.INFO, label, f"'{names[0]}' not found on PATH; {extra}")


def _integration_checks(cfg: EgressVeilConfig) -> list[Check]:
    anthropic = _base_url_state("ANTHROPIC_BASE_URL", cfg)
    openai = "; ".join(
        _base_url_state(v, cfg, OPENAI_MOUNT_PATH) for v in ("OPENAI_BASE_URL", "OPENAI_API_BASE")
    )
    return [
        _check_tool(("claude",), "claude code", anthropic),
        _check_tool(("aider",), "aider", f"{anthropic}; {openai}"),
        _check_tool(("openclaw",), "openclaw", "see docs/integrations.md"),
        _check_tool(
            ("cursor",), "cursor", "not supported: Cursor sends model traffic from its servers"
        ),
    ]


def _detector_checks(cfg: EgressVeilConfig) -> list[Check]:
    active = sorted(n for n, d in cfg.detectors.items() if d.enabled)
    providers = sorted(n for n, p in cfg.providers.items() if p.enabled)
    return [
        Check(
            Status.OK if active else Status.WARN,
            "detectors",
            f"active: {', '.join(active) or 'none'}",
        ),
        Check(
            Status.OK if providers else Status.WARN,
            "providers",
            f"enabled: {', '.join(providers) or 'none'}",
        ),
    ]


def run_doctor(config_path: Path | None) -> list[Check]:
    checks: list[Check] = [_check_python(), _check_platform()]
    result = load_config(config_path)
    checks.append(_check_config(result))
    cfg = result.config
    if cfg is not None:
        running = _port_in_use(cfg) and gateway_health(cfg) is not None
        checks.append(_check_port(cfg, running))
        checks.append(_self_test(cfg, running))
        checks.append(_check_audit(cfg))
        checks.append(_check_proxy_env(cfg))
        checks.extend(_integration_checks(cfg))
        checks.extend(_detector_checks(cfg))
    return checks
