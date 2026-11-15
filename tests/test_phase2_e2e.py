"""End-to-end: OpenAI route, disabled providers, upstream proxy, `egressveil run`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web

from egressveil.config import parse_config
from egressveil.launcher import agent_env
from egressveil.proxy import build_components, create_app
from tests import fakes
from tests.helpers import make_config, with_upstream
from tests.test_gateway import API_KEY, client, free_port, run, serve


def _recording_app(record: list[dict[str, Any]]) -> web.Application:
    async def handler(request: web.Request) -> web.StreamResponse:
        record.append(
            {
                "url": str(request.url),
                "path_qs": request.path_qs,
                "headers": dict(request.headers),
                "body": await request.read(),
            }
        )
        return web.json_response({"id": "chatcmpl-1", "object": "chat.completion"})

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


def _gateway_cfg(tmp_path: Path, port: int, upstream: str, **raw: Any) -> Any:
    raw.setdefault("gateway", {})["listen_port"] = port
    raw.setdefault("audit", {"path": str(tmp_path / "audit.jsonl")})
    raw.setdefault("providers", {"anthropic": {"enabled": True}, "openai": {"enabled": True}})
    cfg = make_config(raw)
    for name, p in cfg.providers.items():
        if p.enabled:
            cfg = with_upstream(cfg, upstream, name)
    return cfg


def test_openai_route_forwarded_with_prefix_stripped(tmp_path: Path) -> None:
    record: list[dict[str, Any]] = []
    body = {"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}]}

    async def scenario() -> None:
        async with serve(_recording_app(record)) as up:
            port = free_port()
            cfg = _gateway_cfg(tmp_path, port, f"http://127.0.0.1:{up}")
            app = create_app(build_components(cfg), allow_insecure_upstream=True)
            async with serve(app, port), client() as s:
                async with s.post(
                    f"http://127.0.0.1:{port}/openai/v1/chat/completions?x=1",
                    json=body,
                    headers={"Authorization": f"Bearer {API_KEY}"},
                ) as r:
                    assert r.status == 200
                    assert r.headers["x-egressveil-decision"] == "forward"

    run(scenario())
    (req,) = record
    assert req["path_qs"] == "/v1/chat/completions?x=1"
    assert req["headers"]["Authorization"] == f"Bearer {API_KEY}"
    assert json.loads(req["body"]) == body
    event = json.loads((tmp_path / "audit.jsonl").read_text(encoding="ascii"))
    assert event["provider"] == "openai"
    assert API_KEY not in (tmp_path / "audit.jsonl").read_text(encoding="ascii")


def test_openai_block_uses_openai_error_shape(tmp_path: Path) -> None:
    record: list[dict[str, Any]] = []
    secret = fakes.openai_key()

    async def scenario() -> dict[str, Any]:
        async with serve(_recording_app(record)) as up:
            port = free_port()
            cfg = _gateway_cfg(tmp_path, port, f"http://127.0.0.1:{up}")
            app = create_app(build_components(cfg), allow_insecure_upstream=True)
            async with serve(app, port), client() as s:
                body = {"model": "gpt-5", "messages": [{"role": "user", "content": secret}]}
                async with s.post(
                    f"http://127.0.0.1:{port}/openai/v1/chat/completions", json=body
                ) as r:
                    assert r.status == 400
                    doc: dict[str, Any] = await r.json()
                    return doc

    import asyncio

    doc = asyncio.run(scenario())
    assert record == []
    assert doc["error"]["type"] == "invalid_request_error"
    assert doc["error"]["code"] == "egressveil"
    assert "secrets/openai_api_key" in doc["error"]["message"]
    assert secret not in json.dumps(doc)


def test_disabled_provider_is_refused(tmp_path: Path) -> None:
    record: list[dict[str, Any]] = []

    async def scenario() -> None:
        async with serve(_recording_app(record)) as up:
            port = free_port()
            cfg = _gateway_cfg(
                tmp_path,
                port,
                f"http://127.0.0.1:{up}",
                providers={"anthropic": {"enabled": True}},
            )
            app = create_app(build_components(cfg), allow_insecure_upstream=True)
            async with serve(app, port), client() as s:
                async with s.post(
                    f"http://127.0.0.1:{port}/openai/v1/chat/completions",
                    json={"model": "m", "messages": []},
                ) as r:
                    assert r.status == 404
                    assert "not enabled" in (await r.json())["error"]["message"]

    run(scenario())
    assert record == []


def test_upstream_proxy_is_used(tmp_path: Path) -> None:
    proxied: list[dict[str, Any]] = []

    async def scenario() -> None:
        async with serve(_recording_app(proxied)) as proxy_port:
            port = free_port()
            cfg = _gateway_cfg(
                tmp_path,
                port,
                "http://upstream.invalid:9",
                gateway={"upstream_proxy": f"http://127.0.0.1:{proxy_port}"},
                providers={"anthropic": {"enabled": True}},
            )
            app = create_app(build_components(cfg), allow_insecure_upstream=True)
            async with serve(app, port), client() as s:
                body = {
                    "model": "m",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                }
                async with s.post(
                    f"http://127.0.0.1:{port}/v1/messages",
                    json=body,
                    headers={"x-api-key": API_KEY},
                ) as r:
                    assert r.status == 200

    run(scenario())
    (req,) = proxied
    assert req["url"].startswith("http://upstream.invalid:9/v1/messages")


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("none", True),
        ("env", True),
        ("ENV", True),
        ("http://proxy.corp:3128", True),
        ("https://proxy.corp:3128/", True),
        ("http://user:pw@proxy.corp:3128", False),
        ("socks5://proxy.corp:1080", False),
        ("http://proxy.corp:3128/path", False),
        ("not a url", False),
    ],
)
def test_upstream_proxy_validation(value: str, ok: bool) -> None:
    config, issues = parse_config({"gateway": {"upstream_proxy": value}})
    assert (config is not None) is ok, [str(i) for i in issues]
    assert all("pw@" not in str(i) for i in issues)


def test_hostname_only_options_rejected_elsewhere() -> None:
    config, issues = parse_config({"detectors": {"pii": {"include_private_ips": True}}})
    assert config is None
    assert any(i.path == "detectors.pii.include_private_ips" for i in issues)


# ----------------------------------------------------------------- egressveil run


def test_agent_env_points_providers_at_gateway() -> None:
    cfg = make_config(
        {"gateway": {"listen_port": 9999}, "providers": {"openai": {"enabled": True}}}
    )
    env = agent_env(cfg, {"NO_PROXY": "intranet.local", "ANTHROPIC_BASE_URL": "https://x"})
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9999"
    assert env["OPENAI_BASE_URL"] == env["OPENAI_API_BASE"] == "http://127.0.0.1:9999/openai/v1"
    assert env["NO_PROXY"].split(",")[:2] == ["intranet.local", "127.0.0.1"]
    assert "localhost" in env["NO_PROXY"]


def test_agent_env_skips_disabled_openai() -> None:
    env = agent_env(make_config(), {})
    assert "OPENAI_BASE_URL" not in env
    assert env["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:")


AGENT = (
    "import json, os, urllib.request\n"
    "o = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "h = json.loads(o.open(os.environ['ANTHROPIC_BASE_URL'] + '/_egressveil/health').read())\n"
    "print('BASE=' + os.environ['ANTHROPIC_BASE_URL'])\n"
    "print('HEALTH=' + h['status'])\n"
    "raise SystemExit(5)\n"
)


def _write_cfg(tmp_path: Path, port: int) -> Path:
    cfg = tmp_path / "egressveil.yaml"
    audit = (tmp_path / "audit.jsonl").as_posix()
    cfg.write_text(
        f"gateway:\n  listen_port: {port}\naudit:\n  path: '{audit}'\n", encoding="utf-8"
    )
    return cfg


def test_run_starts_gateway_runs_agent_and_stops(tmp_path: Path) -> None:
    port = free_port()
    cfg = _write_cfg(tmp_path, port)
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "egressveil",
            "run",
            "-c",
            str(cfg),
            "--",
            sys.executable,
            "-c",
            AGENT,
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    assert proc.returncode == 5, proc.stderr  # agent's exit code is propagated
    assert f"BASE=http://127.0.0.1:{port}" in proc.stdout
    assert "HEALTH=ok" in proc.stdout
    assert "(started; log:" in proc.stderr
    assert (tmp_path / "gateway.log").exists()
    # The gateway it started has been stopped again.
    from egressveil.doctor import gateway_health

    assert gateway_health(make_config({"gateway": {"listen_port": port}})) is None


def test_run_no_start_requires_running_gateway(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path, free_port())
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "egressveil",
            "run",
            "--no-start",
            "-c",
            str(cfg),
            "--",
            sys.executable,
            "-c",
            "pass",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2
    assert "not running" in proc.stderr


def test_run_unknown_command(tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path, free_port())
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "egressveil",
            "run",
            "-c",
            str(cfg),
            "--",
            "definitely-not-an-agent-xyz",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2
    assert "not found on PATH" in proc.stderr
