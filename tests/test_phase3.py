"""Phase 3: policy packs, allowlists, extends, response inspection, setup, OpenClaw."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from typer.testing import CliRunner

from egressveil.cli import app, run_doctor
from egressveil.config import (
    config_fingerprint,
    load_config,
    parse_config,
    user_config_dir,
)
from egressveil.inspection import Outcome
from egressveil.policy import PolicyAction
from egressveil.policy.engine import PolicyEngine
from egressveil.proxy import build_components, create_app
from egressveil.responses import WINDOW, ResponseScanner
from tests import fakes
from tests.helpers import inspect, make_config, make_inspector, messages_body, with_upstream
from tests.test_gateway import client, free_port, serve

runner = CliRunner()


def actions(raw: dict[str, Any]) -> dict[str, PolicyAction]:
    cfg = make_config(raw)
    return {r.detector: r.action for r in cfg.policy.rules}


# ----------------------------------------------------------------- packs


@pytest.mark.parametrize(
    ("pack", "expected"),
    [
        (
            "balanced",
            {
                "secrets": "BLOCK",
                "tokens": "BLOCK",
                "pii": "REDACT",
                "internal_hostnames": "REDACT",
            },
        ),
        ("strict", dict.fromkeys(("secrets", "tokens", "pii", "internal_hostnames"), "BLOCK")),
        ("redact", dict.fromkeys(("secrets", "tokens", "pii", "internal_hostnames"), "REDACT")),
        ("audit", dict.fromkeys(("secrets", "tokens", "pii", "internal_hostnames"), "LOG_ONLY")),
    ],
)
def test_policy_packs(pack: str, expected: dict[str, str]) -> None:
    assert {k: v.value for k, v in actions({"policy": {"pack": pack}}).items()} == expected


def test_rules_override_pack_per_detector() -> None:
    got = actions(
        {"policy": {"pack": "strict", "rules": [{"detector": "pii", "action": "REDACT"}]}}
    )
    assert got["pii"] is PolicyAction.REDACT
    assert got["secrets"] is PolicyAction.BLOCK


def test_audit_pack_warns_and_unknown_pack_rejected() -> None:
    config, issues = parse_config({"policy": {"pack": "audit"}})
    assert config is not None
    assert any(i.path == "policy.pack" for i in issues)
    config, issues = parse_config({"policy": {"pack": "yolo"}})
    assert config is None


def test_redact_pack_keeps_session_flowing() -> None:
    verdict = inspect(
        make_inspector({"policy": {"pack": "redact"}}),
        messages_body(f"key {fakes.aws_access_key_id()}"),
    )
    assert verdict.outcome is Outcome.REDACT


# ----------------------------------------------------------------- allowlist


def test_allow_by_digest_suppresses_only_that_value() -> None:
    allowed, other = fakes.github_token(), "gh" + "p_" + fakes.rand(36, seed="other")
    inspector = make_inspector()
    digest = inspector.digest(allowed)
    inspector = make_inspector({"policy": {"allow": [{"digest": digest}]}})
    assert inspect(inspector, messages_body(f"use {allowed}")).outcome is Outcome.FORWARD
    assert inspect(inspector, messages_body(f"use {other}")).outcome is Outcome.BLOCK


def test_allow_by_pattern_scoped_to_detector() -> None:
    inspector = make_inspector(
        {"policy": {"allow": [{"pattern": r"@acme-corp\.io$", "detectors": ["pii"]}]}}
    )
    ours = inspect(inspector, messages_body("mail jane@acme-corp.io"))
    theirs = inspect(inspector, messages_body("mail bob@other-co.io"))
    assert ours.outcome is Outcome.FORWARD
    assert theirs.outcome is Outcome.REDACT


def test_allow_by_rule() -> None:
    inspector = make_inspector({"policy": {"allow": [{"rule": "phone_nanp"}]}})
    assert inspect(inspector, messages_body("call (212) 555-0147")).outcome is Outcome.FORWARD


@pytest.mark.parametrize(
    "entry",
    [
        {"digest": "not-hex"},
        {"rule": "no_such_rule"},
        {"pattern": "(unclosed"},
        {"pattern": "a" * 600},
        {"digest": "0123456789abcdef", "rule": "email"},
        {},
        {"rule": "email", "detectors": ["nope"]},
    ],
)
def test_invalid_allow_entries(entry: dict[str, Any]) -> None:
    config, issues = parse_config({"policy": {"allow": [entry]}})
    assert config is None, issues


def test_allow_pattern_cannot_carry_a_credential() -> None:
    config, issues = parse_config({"policy": {"allow": [{"pattern": fakes.github_token()}]}})
    assert config is None
    assert any("credential" in i.message for i in issues)


# ----------------------------------------------------------------- extends


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_extends_merges_pack_file(tmp_path: Path) -> None:
    _write(
        tmp_path / "team" / "policy.yaml",
        "policy:\n  pack: strict\n  allow:\n    - rule: phone_nanp\n"
        "detectors:\n  internal_hostnames:\n    internal_domains: [team.example]\n",
    )
    project = _write(
        tmp_path / "proj" / "egressveil.yaml",
        "extends: ../team/policy.yaml\n"
        "policy:\n  rules:\n    - {detector: pii, action: REDACT}\n"
        "  allow:\n    - rule: iban\n"
        "detectors:\n  internal_hostnames:\n    internal_domains: [proj.example]\n",
    )
    result = load_config(project)
    assert result.config is not None, [str(i) for i in result.issues]
    cfg = result.config
    acts = {r.detector: r.action for r in cfg.policy.rules}
    assert cfg.policy.pack == "strict"
    assert acts["pii"] is PolicyAction.REDACT and acts["secrets"] is PolicyAction.BLOCK
    assert [e.value for e in cfg.policy.allow] == ["phone_nanp", "iban"]
    assert cfg.detectors["internal_hostnames"].internal_domains == ("team.example", "proj.example")


def test_extends_user_config_for_per_project_override(tmp_path: Path) -> None:
    _write(user_config_dir() / "egressveil.yaml", "policy:\n  pack: redact\n")
    project = _write(
        tmp_path / "p" / "egressveil.yaml", "extends: user\ngateway:\n  listen_port: 9911\n"
    )
    cfg = load_config(project).config
    assert cfg is not None
    assert cfg.policy.pack == "redact"
    assert cfg.gateway.listen_port == 9911


def test_extends_user_missing_is_a_warning(tmp_path: Path) -> None:
    result = load_config(_write(tmp_path / "e.yaml", "extends: [user]\n"))
    assert result.config is not None
    assert any(i.path == "extends" for i in result.warnings)


@pytest.mark.parametrize(
    ("files", "message"),
    [
        ({"a.yaml": "extends: b.yaml\n", "b.yaml": "extends: a.yaml\n"}, "cycle"),
        ({"a.yaml": "extends: missing.yaml\n"}, "not found"),
        ({"a.yaml": "extends: 5\n"}, "list of paths"),
    ],
)
def test_extends_errors(tmp_path: Path, files: dict[str, str], message: str) -> None:
    for name, text in files.items():
        _write(tmp_path / name, text)
    result = load_config(tmp_path / "a.yaml")
    assert result.config is None
    assert message in str(result.errors[0])


def test_extends_rejects_credentials_in_parent(tmp_path: Path) -> None:
    _write(tmp_path / "base.yaml", f"audit:\n  path: {fakes.github_token()}\n")
    result = load_config(_write(tmp_path / "a.yaml", "extends: base.yaml\n"))
    assert result.config is None
    assert fakes.github_token() not in " ".join(str(i) for i in result.issues)


def test_extends_not_allowed_in_parse_config() -> None:
    config, issues = parse_config({"extends": "x.yaml"})
    assert config is None
    assert issues[0].path == "extends"


def test_fingerprint_tracks_config() -> None:
    a, b = make_config(), make_config({"policy": {"pack": "strict"}})
    assert config_fingerprint(a) == config_fingerprint(make_config())
    assert config_fingerprint(a) != config_fingerprint(b)
    assert re.fullmatch(r"[0-9a-f]{12}", config_fingerprint(a))


# ----------------------------------------------------------------- response scanner


def _sse(events: list[dict[str, Any]]) -> bytes:
    return b"".join(f"event: x\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def _feed(scanner: ResponseScanner, data: bytes, step: int = 7) -> list[dict[str, object]]:
    for i in range(0, len(data), step):  # tiny chunks: splits UTF-8, lines and JSON
        scanner.feed(data[i : i + step])
    return scanner.finish()


def test_sse_secret_split_across_anthropic_deltas_is_found() -> None:
    token = fakes.github_token()
    pieces = [token[:5], token[5:17], token[17:]]
    events = [{"type": "message_start", "message": {"id": "m", "model": "claude"}}]
    events += [
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}}
        for p in pieces
    ]
    events += [{"type": "message_stop"}]
    found = _feed(ResponseScanner(make_inspector(), "text/event-stream", 10**6), _sse(events))
    assert [f["rule_id"] for f in found] == ["github_token"]
    assert found[0]["action"] == "LOG_ONLY"
    assert found[0]["policy_action"] == "BLOCK"
    assert token not in json.dumps(found)


def test_sse_openai_chat_chunks_and_done() -> None:
    key = fakes.aws_access_key_id()
    events = [
        {
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"content": key[i : i + 4]}}],
        }
        for i in range(0, len(key), 4)
    ]
    data = _sse(events) + b"data: [DONE]\n\n"
    found = _feed(
        ResponseScanner(make_inspector(), "text/event-stream; charset=utf-8", 10**6), data
    )
    assert [f["rule_id"] for f in found] == ["aws_access_key_id"]


def test_json_response_is_scanned() -> None:
    body = json.dumps({"content": [{"type": "text", "text": "contact jane@acme-corp.io"}]})
    found = _feed(ResponseScanner(make_inspector(), "application/json", 10**6), body.encode())
    assert [f["rule_id"] for f in found] == ["email"]


def test_secret_across_window_boundary_found_once() -> None:
    token = fakes.github_token()
    filler = "x " * ((WINDOW - 10) // 2)
    events = [
        {"delta": {"text": filler + token[:8]}},
        {"delta": {"text": token[8:] + " end"}},
        {"delta": {"text": " y" * WINDOW}},
    ]
    found = _feed(
        ResponseScanner(make_inspector(), "text/event-stream", 10**7), _sse(events), step=4096
    )
    assert [f["rule_id"] for f in found] == ["github_token"]


def test_scanner_respects_allowlist_and_limits() -> None:
    token = fakes.github_token()
    inspector = make_inspector()
    allowed = make_inspector({"policy": {"allow": [{"digest": inspector.digest(token)}]}})
    data = json.dumps({"text": token}).encode()
    assert _feed(ResponseScanner(allowed, "application/json", 10**6), data) == []
    big = ResponseScanner(inspector, "application/json", 16)
    big.feed(data)
    assert big.truncated and big.finish() == []
    assert not ResponseScanner(inspector, "image/png", 10).active


def test_response_inspection_end_to_end(tmp_path: Path) -> None:
    token = fakes.github_token()
    sse = _sse(
        [
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": t}}
            for t in (token[:10], token[10:])
        ]
    )
    seen_headers: list[dict[str, str]] = []

    async def upstream(request: web.Request) -> web.StreamResponse:
        seen_headers.append(dict(request.headers))
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(sse)
        await resp.write_eof()
        return resp

    up_app = web.Application()
    up_app.router.add_route("*", "/{tail:.*}", upstream)

    async def scenario() -> bytes:
        async with serve(up_app) as up:
            port = free_port()
            cfg = with_upstream(
                make_config(
                    {
                        "gateway": {"listen_port": port, "inspect_responses": True},
                        "audit": {"path": str(tmp_path / "audit.jsonl")},
                    }
                ),
                f"http://127.0.0.1:{up}",
            )
            app_ = create_app(build_components(cfg), allow_insecure_upstream=True)
            async with serve(app_, port), client() as s:
                async with s.post(
                    f"http://127.0.0.1:{port}/v1/messages",
                    json=messages_body("hi"),
                    headers={"Accept-Encoding": "gzip"},
                ) as r:
                    return await r.read()

    import asyncio

    received = asyncio.run(scenario())
    assert received == sse  # response is never modified
    assert seen_headers[0]["Accept-Encoding"] == "identity"
    event = json.loads((tmp_path / "audit.jsonl").read_text(encoding="ascii"))
    assert [f["rule_id"] for f in event["response_findings"]] == ["github_token"]
    assert token not in (tmp_path / "audit.jsonl").read_text(encoding="ascii")


# ----------------------------------------------------------------- CLI: scan, setup, doctor


def test_scan_digest_can_be_allowlisted(
    tmp_path: Path, write_config: Callable[[str], Path]
) -> None:
    target = tmp_path / "notes.txt"
    target.write_text(f"token {fakes.github_token()}\n", encoding="utf-8")
    audit = (tmp_path / "a" / "audit.jsonl").as_posix()
    cfg = write_config(f"audit:\n  path: '{audit}'\n")
    first = runner.invoke(app, ["scan", "-c", str(cfg), str(target)])
    assert first.exit_code == 1
    digest = re.search(r"digest=([0-9a-f]{16})", first.output)
    assert digest is not None
    cfg2 = write_config(
        f"audit:\n  path: '{audit}'\npolicy:\n  allow:\n    - digest: {digest.group(1)}\n",
        name="allow.yaml",
    )
    second = runner.invoke(app, ["scan", "-c", str(cfg2), str(target)])
    assert second.exit_code == 0, second.output


@pytest.mark.parametrize(
    ("agent", "needle"),
    [
        ("claude-code", "egressveil run -- claude"),
        ("aider", "egressveil run -- aider"),
        ("openclaw", 'anthropic: { baseUrl: "http://127.0.0.1:8787" }'),
        ("cursor", "NOT supported"),
    ],
)
def test_setup_instructions(agent: str, needle: str) -> None:
    result = runner.invoke(app, ["setup", agent])
    assert result.exit_code == 0
    assert needle in result.output


def test_setup_openclaw_includes_openai_when_enabled(write_config: Callable[[str], Path]) -> None:
    cfg = write_config("providers:\n  openai:\n    enabled: true\n")
    result = runner.invoke(app, ["setup", "openclaw", "-c", str(cfg)])
    assert 'baseUrl: "http://127.0.0.1:8787/openai/v1", api: "openai-completions"' in result.output


def test_setup_unknown_agent() -> None:
    assert runner.invoke(app, ["setup", "notepad"]).exit_code == 2


def test_doctor_openclaw_check(isolated_env: Path, tmp_path: Path) -> None:
    def detail() -> str:
        return next(c.detail for c in run_doctor(None) if c.name == "openclaw")

    assert "egressveil setup openclaw" in detail()
    oc = tmp_path / "home" / ".openclaw" / "openclaw.json"
    _write(oc, '{ models: { providers: { anthropic: { baseUrl: "https://api.anthropic.com" } } } }')
    assert "no provider baseUrl points at the gateway" in detail()
    _write(oc, '{ models: { providers: { anthropic: { baseUrl: "http://127.0.0.1:8787" } } } }')
    assert "pointing at the gateway" in detail()


def test_run_warns_when_running_gateway_has_other_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io
    import sys

    from egressveil import launcher

    cfg = make_config()
    monkeypatch.setattr(launcher, "gateway_health", lambda _c: {"config": "different"})
    out = io.StringIO()
    code = launcher.run_agent([sys.executable, "-c", "pass"], cfg, None, notify=out)
    assert code == 0
    assert "different configuration" in out.getvalue()
    monkeypatch.setattr(launcher, "gateway_health", lambda _c: {"config": config_fingerprint(cfg)})
    out = io.StringIO()
    launcher.run_agent([sys.executable, "-c", "pass"], cfg, None, notify=out)
    assert "different configuration" not in out.getvalue()


def test_policy_engine_unchanged_api() -> None:
    engine = PolicyEngine(make_config({"policy": {"pack": "audit"}}).policy)
    from egressveil.detectors import Finding

    assert engine.action_for(Finding("secrets", "x", 0, 1, 1.0)) is PolicyAction.LOG_ONLY
