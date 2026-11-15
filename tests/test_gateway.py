"""End-to-end tests: agent -> EgressVeil gateway -> mock upstream.

The mock upstream is a local plain-HTTP aiohttp server; no real API is called.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp import web

from egressveil.proxy import HEALTH_PATH, build_components, create_app
from tests import fakes
from tests.helpers import make_config, messages_body, with_upstream

API_KEY = "test-key-" + fakes.rand(24)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@dataclass
class Upstream:
    url: str
    requests: list[dict[str, Any]] = field(default_factory=list)


Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


async def _echo(request: web.Request) -> web.StreamResponse:
    return web.json_response({"type": "message", "content": [{"type": "text", "text": "ok"}]})


@asynccontextmanager
async def serve(app: web.Application, port: int = 0) -> AsyncIterator[int]:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    try:
        yield int(runner.addresses[0][1])
    finally:
        await runner.cleanup()


@asynccontextmanager
async def stack(
    tmp_path: Path,
    raw_config: dict[str, Any] | None = None,
    handler: Handler = _echo,
) -> AsyncIterator[tuple[str, Upstream]]:
    """Start mock upstream + gateway; yield (gateway base URL, upstream record)."""
    upstream_app = web.Application()
    record = Upstream(url="")

    async def recording(request: web.Request) -> web.StreamResponse:
        record.requests.append(
            {
                "method": request.method,
                "path_qs": request.path_qs,
                "headers": dict(request.headers),
                "body": await request.read(),
            }
        )
        return await handler(request)

    upstream_app.router.add_route("*", "/{tail:.*}", recording)
    async with serve(upstream_app) as up_port:
        record.url = f"http://127.0.0.1:{up_port}"
        port = free_port()
        raw = dict(raw_config or {})
        raw.setdefault("audit", {"path": str(tmp_path / "audit.jsonl")})
        gateway_cfg = raw.setdefault("gateway", {})
        gateway_cfg["listen_port"] = port
        cfg = with_upstream(make_config(raw), record.url)
        app = create_app(build_components(cfg), allow_insecure_upstream=True)
        async with serve(app, port):
            yield f"http://127.0.0.1:{port}", record


def run(coro: Awaitable[None]) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def client() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(auto_decompress=False)


HEADERS = {
    "x-api-key": API_KEY,
    "anthropic-version": "2023-06-01",
    "content-type": "application/json",
}

# ----------------------------------------------------------------- forwarding


def test_clean_request_is_forwarded_verbatim(tmp_path: Path) -> None:
    raw = json.dumps(messages_body("hello")).encode()

    async def scenario() -> None:
        async with stack(tmp_path) as (base, up), client() as s:
            async with s.post(f"{base}/v1/messages?beta=true", data=raw, headers=HEADERS) as r:
                assert r.status == 200
                assert (await r.json())["type"] == "message"
                assert r.headers["x-egressveil-decision"] == "forward"
                assert r.headers["x-egressveil-request-id"].startswith("ev_")
        (req,) = up.requests
        assert req["body"] == raw
        assert req["path_qs"] == "/v1/messages?beta=true"
        assert req["headers"]["x-api-key"] == API_KEY
        assert req["headers"]["anthropic-version"] == "2023-06-01"
        assert req["headers"]["Host"] == up.url.removeprefix("http://")

    run(scenario())
    (event,) = audit_events(tmp_path)
    assert event["outcome"] == "forward"
    assert event["upstream_status"] == 200
    assert event["stream_complete"] is True
    assert event["path"] == "/v1/messages"
    text = (tmp_path / "audit.jsonl").read_text(encoding="ascii")
    assert API_KEY not in text
    assert "beta=true" not in text


def test_secret_is_blocked_and_never_reaches_upstream(tmp_path: Path) -> None:
    secret = fakes.github_token()

    async def scenario() -> None:
        async with (
            stack(tmp_path) as (base, up),
            client() as s,
            s.post(
                f"{base}/v1/messages", json=messages_body(f"use {secret}"), headers=HEADERS
            ) as r,
        ):
            assert r.status == 400
            assert r.headers["x-egressveil-decision"] == "block"
            body = await r.json()
            text = json.dumps(body)
        assert up.requests == []
        assert body["type"] == "error"
        assert body["error"]["type"] == "invalid_request_error"
        assert "secrets/github_token" in body["error"]["message"]
        assert secret not in text

    run(scenario())
    (event,) = audit_events(tmp_path)
    assert event["outcome"] == "block"
    assert event["reason"] == "policy"
    assert event["findings"][0]["rule_id"] == "github_token"
    assert secret not in (tmp_path / "audit.jsonl").read_text(encoding="ascii")


def test_redaction_sends_placeholder_upstream(tmp_path: Path) -> None:
    secret = fakes.aws_access_key_id()
    cfg = {"policy": {"rules": [{"detector": "secrets", "action": "REDACT"}]}}

    async def scenario() -> None:
        async with (
            stack(tmp_path, cfg) as (base, up),
            client() as s,
            s.post(
                f"{base}/v1/messages", json=messages_body(f"key={secret}"), headers=HEADERS
            ) as r,
        ):
            assert r.status == 200
            assert r.headers["x-egressveil-decision"] == "redact"
        sent = up.requests[0]["body"].decode()
        assert secret not in sent
        assert "[EGRESSVEIL:aws_access_key_id:" in sent
        assert json.loads(sent)["messages"][0]["role"] == "user"

    run(scenario())
    assert audit_events(tmp_path)[0]["outcome"] == "redact"


def test_streaming_sse_passthrough(tmp_path: Path) -> None:
    events = [
        b'event: message_start\ndata: {"type":"message_start"}\n\n',
        b'event: content_block_delta\ndata: {"delta":{"text":"hi"}}\n\n',
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ]

    async def sse(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        for e in events:
            await resp.write(e)
            await asyncio.sleep(0.05)
        await resp.write_eof()
        return resp

    async def scenario() -> None:
        async with stack(tmp_path, handler=sse) as (base, _), client() as s:
            body = messages_body("hi", stream=True)
            async with s.post(f"{base}/v1/messages", json=body, headers=HEADERS) as r:
                assert r.status == 200
                assert r.headers["Content-Type"] == "text/event-stream"
                received = b""
                chunks = 0
                async for chunk in r.content.iter_any():
                    received += chunk
                    chunks += 1
        assert received == b"".join(events)
        assert chunks >= 2  # delivered incrementally, not buffered whole

    run(scenario())


def test_upstream_errors_and_headers_relayed(tmp_path: Path) -> None:
    async def limited(request: web.Request) -> web.StreamResponse:
        return web.json_response(
            {"type": "error", "error": {"type": "rate_limit_error", "message": "slow"}},
            status=429,
            headers={"retry-after": "7", "request-id": "req_up"},
        )

    async def scenario() -> None:
        async with stack(tmp_path, handler=limited) as (base, _), client() as s:
            async with s.post(f"{base}/v1/messages", json=messages_body("x"), headers=HEADERS) as r:
                assert r.status == 429
                assert r.headers["retry-after"] == "7"
                assert r.headers["request-id"] == "req_up"
                assert (await r.json())["error"]["type"] == "rate_limit_error"

    run(scenario())


def test_compressed_response_is_not_decoded(tmp_path: Path) -> None:
    payload = gzip.compress(b'{"type":"message"}')

    async def gz(request: web.Request) -> web.StreamResponse:
        return web.Response(
            body=payload, headers={"Content-Encoding": "gzip", "Content-Type": "application/json"}
        )

    async def scenario() -> None:
        async with stack(tmp_path, handler=gz) as (base, _), client() as s:
            async with s.post(f"{base}/v1/messages", json=messages_body("x"), headers=HEADERS) as r:
                assert r.headers["Content-Encoding"] == "gzip"
                assert await r.read() == payload

    run(scenario())


def test_upstream_redirect_is_not_followed(tmp_path: Path) -> None:
    async def redirect(request: web.Request) -> web.StreamResponse:
        return web.Response(status=307, headers={"Location": "https://evil.example/collect"})

    async def scenario() -> None:
        async with (
            stack(tmp_path, handler=redirect) as (base, up),
            client() as s,
            s.post(
                f"{base}/v1/messages",
                json=messages_body("x"),
                headers=HEADERS,
                allow_redirects=False,
            ) as r,
        ):
            assert r.status == 307
        assert len(up.requests) == 1

    run(scenario())


def test_bodyless_get_forwarded(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with stack(tmp_path) as (base, up), client() as s:
            async with s.get(f"{base}/v1/models", headers={"x-api-key": API_KEY}) as r:
                assert r.status == 200
        assert up.requests[0]["method"] == "GET"
        assert up.requests[0]["path_qs"] == "/v1/models"

    run(scenario())


# ----------------------------------------------------------------- fail closed


def test_unsupported_route_blocked_in_strict_mode(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with stack(tmp_path) as (base, up), client() as s:
            async with s.post(f"{base}/v1/files", data=b"x", headers=HEADERS) as r:
                assert r.status == 400
                assert "not supported" in (await r.json())["error"]["message"]
        assert up.requests == []

    run(scenario())
    assert audit_events(tmp_path)[0]["reason"] == "unsupported_route"


def test_unsupported_route_forwarded_in_permissive_mode(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with (
            stack(tmp_path, {"gateway": {"mode": "permissive"}}) as (base, up),
            client() as s,
            s.post(f"{base}/v1/files", data=b"x", headers=HEADERS) as r,
        ):
            assert r.status == 200
        assert up.requests[0]["body"] == b"x"

    run(scenario())
    event = audit_events(tmp_path)[0]
    assert event["inspected"] is False
    assert event["reason"] == "unsupported_route"


@pytest.mark.parametrize("chunked", [False, True])
def test_oversized_body_rejected(tmp_path: Path, chunked: bool) -> None:
    cfg = {"gateway": {"max_request_body_bytes": 1024}}
    big = json.dumps(messages_body("x" * 4000)).encode()

    async def body_gen() -> AsyncIterator[bytes]:
        for i in range(0, len(big), 500):
            yield big[i : i + 500]

    async def scenario() -> None:
        async with stack(tmp_path, cfg) as (base, up), client() as s:
            data: Any = body_gen() if chunked else big
            async with s.post(f"{base}/v1/messages", data=data, headers=HEADERS) as r:
                assert r.status == 413
                assert (await r.json())["error"]["type"] == "request_too_large"
        assert up.requests == []

    run(scenario())


def test_upstream_unreachable_returns_502(tmp_path: Path) -> None:
    dead = free_port()

    async def scenario() -> None:
        port = free_port()
        cfg = with_upstream(
            make_config(
                {"gateway": {"listen_port": port}, "audit": {"path": str(tmp_path / "a.jsonl")}}
            ),
            f"http://127.0.0.1:{dead}",
        )
        app = create_app(build_components(cfg), allow_insecure_upstream=True)
        async with (
            serve(app, port),
            client() as s,
            s.post(
                f"http://127.0.0.1:{port}/v1/messages", json=messages_body("x"), headers=HEADERS
            ) as r,
        ):
            assert r.status == 502
            assert (await r.json())["error"]["type"] == "api_error"

    run(scenario())


# ----------------------------------------------------------------- local hardening


def test_foreign_host_header_rejected(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with stack(tmp_path) as (base, up), client() as s:
            headers = {**HEADERS, "Host": "attacker.example"}
            async with s.post(f"{base}/v1/messages", json=messages_body("x"), headers=headers) as r:
                assert r.status == 403
        assert up.requests == []

    run(scenario())
    assert audit_events(tmp_path)[0]["reason"] == "bad_host"


def test_browser_origin_rejected(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with stack(tmp_path) as (base, up), client() as s:
            headers = {**HEADERS, "Origin": "https://evil.example"}
            async with s.post(f"{base}/v1/messages", json=messages_body("x"), headers=headers) as r:
                assert r.status == 403
        assert up.requests == []

    run(scenario())


def test_health_endpoint_is_local(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with stack(tmp_path) as (base, up), client() as s:
            async with s.get(f"{base}{HEALTH_PATH}") as r:
                doc = await r.json()
            async with s.get(f"{base}/_egressveil/other") as r2:
                assert r2.status == 404
        assert doc["status"] == "ok"
        assert doc["service"] == "egressveil"
        assert doc["mode"] == "strict"
        assert up.requests == []

    run(scenario())


def test_insecure_upstream_refused_by_default(tmp_path: Path) -> None:
    cfg = with_upstream(
        make_config({"audit": {"path": str(tmp_path / "a.jsonl")}}), "http://127.0.0.1:1"
    )
    with pytest.raises(ValueError, match="https"):
        create_app(build_components(cfg))


def test_disabled_anthropic_provider_cannot_serve(tmp_path: Path) -> None:
    cfg = make_config({"providers": {"anthropic": {"enabled": False}}})
    with pytest.raises(ValueError, match="disabled"):
        build_components(cfg)
