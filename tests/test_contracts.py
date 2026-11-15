"""Public-contract tests: docs, schemas and real gateway output must agree.

If one of these fails, either the code changed a public surface (see
docs/versioning.md) or a document is out of date.
"""

from __future__ import annotations

import asyncio
import importlib.resources
import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from aiohttp import web

from egressveil import config as cfgmod
from egressveil.cli import app
from egressveil.proxy import build_components, create_app
from tests import fakes
from tests.helpers import make_config, messages_body, with_upstream
from tests.test_gateway import client, free_port, serve

DOCS = Path(__file__).resolve().parent.parent / "docs"


def load_schema(name: str) -> dict[str, Any]:
    text = importlib.resources.files("egressveil.schemas").joinpath(name).read_text("utf-8")
    schema: dict[str, Any] = json.loads(text)
    jsonschema.Draft202012Validator.check_schema(schema)
    return schema


AUDIT_SCHEMA = load_schema("audit-event-v1.schema.json")
HEALTH_SCHEMA = load_schema("health-v1.schema.json")


# ----------------------------------------------------------------- docs cover the code


@pytest.mark.parametrize(
    "keyset",
    [
        "_ROOT_KEYS",
        "_GATEWAY_KEYS",
        "_PROVIDER_KEYS",
        "_POLICY_KEYS",
        "_ALLOW_KEYS",
        "_RULE_KEYS",
        "_DETECTOR_KEYS",
        "_AUDIT_KEYS",
        "_TELEMETRY_KEYS",
    ],
)
def test_every_config_key_is_documented(keyset: str) -> None:
    doc = (DOCS / "configuration.md").read_text(encoding="utf-8")
    missing = [k for k in getattr(cfgmod, keyset) if f"`{k}`" not in doc]
    assert missing == [], f"undocumented config keys in {keyset}: {missing}"


def test_every_policy_pack_is_documented() -> None:
    doc = (DOCS / "configuration.md").read_text(encoding="utf-8")
    assert all(f"`{pack}`" in doc for pack in cfgmod.POLICY_PACKS)


def test_every_cli_command_is_documented() -> None:
    doc = (DOCS / "cli.md").read_text(encoding="utf-8")
    names = [c.name or c.callback.__name__ for c in app.registered_commands if c.callback]
    assert names, "no commands found"
    missing = [n for n in names if f"egressveil {n}" not in doc]
    assert missing == []
    assert "egressveil config validate" in doc


def test_versioning_policy_links_all_contract_docs() -> None:
    doc = (DOCS / "versioning.md").read_text(encoding="utf-8")
    for target in ("configuration.md", "cli.md", "audit-log.md"):
        assert target in doc


# ----------------------------------------------------------------- audit events vs schema


def _audit_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def test_audit_events_from_real_traffic_match_schema(tmp_path: Path) -> None:
    sse = (
        b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"'
        + fakes.github_token().encode()
        + b'"}}\n\n'
    )

    async def upstream(request: web.Request) -> web.StreamResponse:
        if request.path == "/v1/stream":
            resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await resp.prepare(request)
            await resp.write(sse)
            await resp.write_eof()
            return resp
        return web.json_response({"type": "message"})

    up_app = web.Application()
    up_app.router.add_route("*", "/{tail:.*}", upstream)
    audit = tmp_path / "audit.jsonl"

    async def scenario() -> dict[str, Any]:
        async with serve(up_app) as up:
            port = free_port()
            cfg = with_upstream(
                make_config(
                    {
                        "gateway": {
                            "listen_port": port,
                            "inspect_responses": True,
                            "max_request_body_bytes": 4096,
                        },
                        "providers": {"openai": {"enabled": True}},
                        "audit": {"path": str(audit)},
                        "policy": {"rules": [{"detector": "pii", "action": "REDACT"}]},
                    }
                ),
                f"http://127.0.0.1:{up}",
            )
            cfg = with_upstream(cfg, f"http://127.0.0.1:{up}", "openai")
            app_ = create_app(build_components(cfg), allow_insecure_upstream=True)
            base = f"http://127.0.0.1:{port}"
            async with serve(app_, port), client() as s:
                async with s.get(f"{base}/_egressveil/health") as r:
                    health: dict[str, Any] = await r.json()
                calls = [
                    ("POST", "/v1/messages", messages_body("hello"), {}),  # forward
                    ("POST", "/v1/messages", messages_body(fakes.github_token()), {}),  # block
                    ("POST", "/v1/messages", messages_body("mail jane@acme-corp.io"), {}),  # redact
                    (
                        "POST",
                        "/v1/messages?to=jane%40acme-corp.io",
                        messages_body("x"),
                        {},
                    ),  # escalated
                    (
                        "POST",
                        "/v1/messages",
                        messages_body(
                            [
                                {
                                    "type": "thinking",
                                    "thinking": fakes.github_token(),
                                    "signature": "s",
                                }
                            ]
                        ),
                        {},
                    ),  # signed
                    ("POST", "/v1/files", {"x": 1}, {}),  # unsupported
                    ("POST", "/v1/messages", messages_body("x" * 5000), {}),  # too large
                    ("POST", "/v1/messages", messages_body("x"), {"Host": "evil.example"}),
                    ("POST", "/v1/messages", messages_body("x"), {"Origin": "https://e.x"}),
                    (
                        "POST",
                        "/openai/v1/chat/completions",
                        {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
                        {},
                    ),
                    ("POST", "/v1/stream", messages_body("hi"), {}),  # response
                ]
                for method, path, body, headers in calls:
                    async with s.request(method, base + path, json=body, headers=headers) as r:
                        await r.read()
                # A bodyless GET is forwarded, so its streamed response is inspected.
                async with s.get(f"{base}/v1/stream") as r:
                    await r.read()
            return health

    health = asyncio.run(scenario())
    jsonschema.validate(health, HEALTH_SCHEMA)

    events = _audit_lines(audit)
    assert len(events) >= 12
    for event in events:
        jsonschema.validate(event, AUDIT_SCHEMA)
    outcomes = {e["outcome"] for e in events}
    assert {"forward", "block", "redact"} <= outcomes
    flags = {
        k
        for e in events
        for f in e.get("findings", [])
        for k in ("escalated", "signed")
        if f.get(k)
    }
    assert flags == {"escalated", "signed"}
    assert any(e.get("response_findings") for e in events)
    reasons = {e.get("reason") for e in events}
    assert {
        "policy",
        "unsupported_route",
        "body_too_large",
        "bad_host",
        "browser_origin",
    } <= reasons
    text = audit.read_text(encoding="ascii")
    assert fakes.github_token() not in text
    assert "jane@acme-corp.io" not in text


def test_unreachable_upstream_event_matches_schema(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"

    async def scenario() -> None:
        port = free_port()
        cfg = with_upstream(
            make_config({"gateway": {"listen_port": port}, "audit": {"path": str(audit)}}),
            f"http://127.0.0.1:{free_port()}",
        )
        app_ = create_app(build_components(cfg), allow_insecure_upstream=True)
        async with serve(app_, port), client() as s:
            async with s.post(f"http://127.0.0.1:{port}/v1/messages", json=messages_body("x")) as r:
                assert r.status == 502

    asyncio.run(scenario())
    (event,) = _audit_lines(audit)
    jsonschema.validate(event, AUDIT_SCHEMA)
    assert event["outcome"] == "error"


def test_schema_rejects_raw_values_shape() -> None:
    bad = {
        "schema_version": 1,
        "ts": "t",
        "request_id": "ev_0123456789abcdef",
        "provider": "anthropic",
        "method": "POST",
        "path": "/",
        "duration_ms": 1,
        "outcome": "block",
        "findings": [
            {
                "detector": "secrets",
                "rule_id": "x",
                "location": "l",
                "action": "BLOCK",
                "digest": "0123456789abcdef",
                "value": "leaked",
            }
        ],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, AUDIT_SCHEMA)


def test_schema_files_ship_in_wheel_layout() -> None:
    root = importlib.resources.files("egressveil.schemas")
    names = {p.name for p in root.iterdir() if p.name.endswith(".json")}
    assert names == {"audit-event-v1.schema.json", "health-v1.schema.json"}
    assert re.fullmatch(r"\d+", str(AUDIT_SCHEMA["properties"]["schema_version"]["const"]))
