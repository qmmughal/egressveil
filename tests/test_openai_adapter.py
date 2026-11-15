from __future__ import annotations

import json
from typing import Any

import pytest

from egressveil.config import parse_config
from egressveil.inspection import Outcome
from egressveil.providers import adapter_for_path
from egressveil.providers.base import RouteKind, data_uri_kind
from egressveil.providers.openai import ADAPTER as OPENAI
from tests import fakes
from tests.helpers import inspect, make_inspector, policy


def chat(*contents: Any, **extra: Any) -> dict[str, Any]:
    return {
        "model": "gpt-5",
        "messages": [{"role": "user", "content": c} for c in contents],
        **extra,
    }


def go(body: dict[str, Any] | bytes, path: str = "/v1/chat/completions", **cfg: Any) -> Any:
    return inspect(make_inspector(cfg or None), body, path=path, adapter=OPENAI)


@pytest.mark.parametrize(
    ("path", "adapter", "upstream"),
    [
        ("/v1/messages", "anthropic", "/v1/messages"),
        ("/openai/v1/chat/completions", "openai", "/v1/chat/completions"),
        ("/openai", "openai", "/"),
        ("/openaiX/v1/models", "anthropic", "/openaiX/v1/models"),
    ],
)
def test_adapter_for_path(path: str, adapter: str, upstream: str) -> None:
    a, p = adapter_for_path(path)
    assert (a.name, p) == (adapter, upstream)


@pytest.mark.parametrize(
    ("method", "path", "kind"),
    [
        ("POST", "/v1/chat/completions", RouteKind.JSON_INSPECT),
        ("POST", "/v1/responses", RouteKind.JSON_INSPECT),
        ("POST", "/v1/completions", RouteKind.JSON_INSPECT),
        ("POST", "/v1/embeddings", RouteKind.JSON_INSPECT),
        ("POST", "/v1/messages", RouteKind.UNSUPPORTED),
        ("POST", "/v1/files", RouteKind.UNSUPPORTED),
        ("GET", "/v1/models", RouteKind.BODYLESS),
    ],
)
def test_openai_routes(method: str, path: str, kind: RouteKind) -> None:
    assert OPENAI.classify(method, path, has_body=method == "POST") is kind


def test_clean_chat_forwarded() -> None:
    raw = json.dumps(chat("explain this regex")).encode()
    verdict = go(raw)
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.body is raw


def test_secret_in_tool_message_blocked() -> None:
    body = {
        "model": "gpt-5",
        "messages": [
            {"role": "user", "content": "read the env file"},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "read", "arguments": '{"path": ".env"}'},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": f"KEY={fakes.openai_key()}"},
        ],
    }
    verdict = go(body)
    assert verdict.outcome is Outcome.BLOCK
    assert "messages[2].content" in (verdict.message or "")


def test_secret_in_function_arguments_redacted() -> None:
    token = fakes.github_token()
    body = chat(
        "x",
        tools=[
            {
                "type": "function",
                "function": {"name": "t", "description": f"uses {token}", "parameters": {}},
            }
        ],
    )
    verdict = inspect(
        make_inspector(policy(secrets="REDACT")), body, path="/v1/chat/completions", adapter=OPENAI
    )
    assert verdict.outcome is Outcome.REDACT
    assert token not in verdict.body.decode()


def test_responses_api_input_inspected() -> None:
    body = {
        "model": "gpt-5",
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": fakes.aws_access_key_id()}]}
        ],
    }
    assert go(body, path="/v1/responses").outcome is Outcome.BLOCK


def test_embeddings_input_inspected() -> None:
    body = {"model": "text-embedding-3-small", "input": [f"x {fakes.stripe_key()}"]}
    assert go(body, path="/v1/embeddings").outcome is Outcome.BLOCK


@pytest.mark.parametrize(
    "part",
    [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
        {"type": "input_image", "image_url": "data:image/jpeg;base64,/9j/4AAQ"},
        {"type": "input_audio", "input_audio": {"data": "UklGRg==", "format": "wav"}},
        {"type": "file", "file": {"filename": "a.pdf", "file_data": "JVBERi0x"}},
    ],
)
def test_opaque_parts_blocked_in_strict_mode(part: dict[str, Any]) -> None:
    verdict = go(chat([part, {"type": "text", "text": "what is this?"}]))
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.reason == "opaque_content"


def test_remote_image_url_is_text_not_opaque() -> None:
    part = {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}}
    assert go(chat([part])).outcome is Outcome.FORWARD


def test_encrypted_reasoning_skipped() -> None:
    body = {
        "model": "gpt-5",
        "input": [{"type": "reasoning", "id": "rs_1", "encrypted_content": fakes.github_token()}],
    }
    assert go(body, path="/v1/responses").outcome is Outcome.FORWARD


def test_pii_redacted_by_default() -> None:
    verdict = go(chat("email the report to jane.doe@acme-corp.io please"))
    assert verdict.outcome is Outcome.REDACT
    text = json.loads(verdict.body)["messages"][0]["content"]
    assert "jane.doe@acme-corp.io" not in text
    assert "[EGRESSVEIL:email:" in text


def test_internal_hostname_redacted_by_default() -> None:
    config, _ = parse_config(
        {"detectors": {"internal_hostnames": {"internal_domains": ["corp.example.com"]}}}
    )
    assert config is not None
    verdict = go(
        chat("deploy to api.corp.example.com"),
        detectors={"internal_hostnames": {"internal_domains": ["corp.example.com"]}},
    )
    assert verdict.outcome is Outcome.REDACT
    assert "api.corp.example.com" not in verdict.body.decode()


def test_data_uri_kind() -> None:
    assert data_uri_kind("data:image/png;base64,AAAA") == "image/png"
    assert data_uri_kind("data:;base64,AAAA") == "binary"
    assert data_uri_kind("data:text/plain,hello") is None
    assert data_uri_kind("just text") is None
