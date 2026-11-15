"""``egressveil run -- <agent> [args...]``: run an agent through the gateway.

Starts the gateway in the background when it is not already running, launches
the agent with its base-URL environment variables pointing at the gateway,
and stops the gateway again when the agent exits (only if this command
started it).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import IO, Final

from egressveil.config import EgressVeilConfig, config_fingerprint
from egressveil.doctor import OPENAI_MOUNT_PATH, gateway_base_url, gateway_health

__all__ = ["LaunchError", "agent_env", "run_agent"]

_LOOPBACK_NO_PROXY: Final = ("127.0.0.1", "localhost", "::1")
STARTUP_TIMEOUT: Final = 20.0


class LaunchError(Exception):
    pass


def agent_env(cfg: EgressVeilConfig, base: Mapping[str, str]) -> dict[str, str]:
    """Environment for the agent: provider base URLs -> gateway, loopback not proxied."""
    env = dict(base)
    url = gateway_base_url(cfg)
    env["EGRESSVEIL_GATEWAY"] = url
    if cfg.providers["anthropic"].enabled:
        env["ANTHROPIC_BASE_URL"] = url
    if cfg.providers["openai"].enabled:
        env["OPENAI_BASE_URL"] = env["OPENAI_API_BASE"] = url + OPENAI_MOUNT_PATH
    # An agent honouring HTTP(S)_PROXY must not send loopback traffic to the proxy.
    existing = env.get("NO_PROXY") or env.get("no_proxy") or ""
    entries = [e.strip() for e in existing.split(",") if e.strip()]
    entries += [h for h in _LOOPBACK_NO_PROXY if h not in entries]
    env["NO_PROXY"] = ",".join(entries)
    if os.name != "nt":  # Windows environment names are case-insensitive
        env["no_proxy"] = env["NO_PROXY"]
    return env


def _log_path(cfg: EgressVeilConfig) -> Path:
    if cfg.audit.enabled:
        return cfg.audit.resolved_path.parent / "gateway.log"
    return Path.home() / ".egressveil" / "gateway.log"


def _spawn_gateway(
    cfg: EgressVeilConfig, config_path: Path | None
) -> tuple[subprocess.Popen[bytes], IO[bytes], Path]:
    log_path = _log_path(cfg)
    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    log = log_path.open("ab")
    args = [sys.executable, "-m", "egressveil", "serve"]
    if config_path is not None:
        args += ["--config", str(config_path)]
    kwargs: dict[str, object] = {}
    if os.name == "nt":
        # Own process group: Ctrl+C meant for the agent must not kill the gateway.
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(  # noqa: S603 - our own interpreter and module
        args,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        **kwargs,  # type: ignore[call-overload]
    )
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if gateway_health(cfg) is not None:
            return proc, log, log_path
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    _stop(proc)
    log.close()
    tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
    raise LaunchError("gateway failed to start:\n  " + "\n  ".join(tail))


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def run_agent(
    command: list[str],
    cfg: EgressVeilConfig,
    config_path: Path | None,
    *,
    start_gateway: bool = True,
    notify: IO[str] | None = None,
) -> int:
    if not command:
        raise LaunchError("no agent command given (usage: egressveil run -- claude)")
    executable = shutil.which(command[0])
    if executable is None:
        raise LaunchError(f"'{command[0]}' was not found on PATH")

    spawned: tuple[subprocess.Popen[bytes], IO[bytes], Path] | None = None
    out = notify or sys.stderr
    health = gateway_health(cfg)
    if health is None:
        if not start_gateway:
            raise LaunchError("the gateway is not running (start it with 'egressveil serve')")
        spawned = _spawn_gateway(cfg, config_path)
        state = f"started; log: {spawned[2]}"
    else:
        state = "already running"
        if health.get("config") != config_fingerprint(cfg):
            print(
                "egressveil: warning: the running gateway was started with a different "
                "configuration than this directory's; restart it to apply this one",
                file=out,
            )
    print(f"egressveil: routing {command[0]} through {gateway_base_url(cfg)} ({state})", file=out)

    try:
        child = subprocess.Popen(  # noqa: S603 - the user's own command
            [executable, *command[1:]], env=agent_env(cfg, os.environ)
        )
        while True:
            try:
                return child.wait()
            except KeyboardInterrupt:
                continue  # the agent receives Ctrl+C itself and decides what to do
    finally:
        if spawned is not None:
            _stop(spawned[0])
            spawned[1].close()
