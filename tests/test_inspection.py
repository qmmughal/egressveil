from __future__ import annotations

import json
from typing import Any

import pytest

from egressveil.detectors import Finding
from egressveil.inspection import URL_LOCATION, Inspector, Outcome
from egressveil.policy import GatewayMode, PolicyAction
from egressveil.policy.engine import PolicyEngine, most_restrictive
from egressveil.providers.anthropic import ADAPTER as ANTHROPIC
from egressveil.providers.base import RouteKind
from egressveil.redactor import PLACEHOLDER_PREFIX, Redactor
from tests import fakes
from tests.helpers import KEY, inspect, make_config, make_inspector, messages_body, policy

# ----------------------------------------------------------------- routing


@pytest.mark.parametrize(
    ("method", "path", "has_body", "kind"),
    [
        ("POST", "/v1/messages", True, RouteKind.JSON_INSPECT),
        ("POST", "/v1/messages/", True, RouteKind.JSON_INSPECT),
        ("POST", "/v1/messages/count_tokens", True, RouteKind.JSON_INSPECT),
        ("GET", "/v1/models", False, RouteKind.BODYLESS),
        ("HEAD", "/v1/models", False, RouteKind.BODYLESS),
        ("GET", "/v1/models", True, RouteKind.UNSUPPORTED),
        ("POST", "/v1/files", True, RouteKind.UNSUPPORTED),
        ("DELETE", "/v1/messages/batches/x", False, RouteKind.UNSUPPORTED),
    ],
)
def test_classify_route(method: str, path: str, has_body: bool, kind: RouteKind) -> None:
    assert ANTHROPIC.classify(method, path, has_body) is kind


# ----------------------------------------------------------------- policy


def test_most_restrictive_order() -> None:
    A = PolicyAction
    assert most_restrictive([]) is A.ALLOW
    assert most_restrictive([A.LOG_ONLY, A.ALLOW]) is A.LOG_ONLY
    assert most_restrictive([A.REDACT, A.LOG_ONLY]) is A.REDACT
    assert most_restrictive([A.REDACT, A.BLOCK, A.ALLOW]) is A.BLOCK


def test_policy_engine_default_action() -> None:
    cfg = make_config(
        {
            "policy": {
                "default_action": "LOG_ONLY",
                "rules": [{"detector": "secrets", "action": "BLOCK"}],
            }
        }
    )
    engine = PolicyEngine(cfg.policy)
    assert engine.action_for(Finding("secrets", "r", 0, 1, 1.0)) is PolicyAction.BLOCK
    # Rules override the pack per detector; tokens keeps the balanced pack's action.
    assert engine.action_for(Finding("tokens", "r", 0, 1, 1.0)) is PolicyAction.BLOCK
    # default_action covers categories no rule mentions.
    assert engine.action_for(Finding("future", "r", 0, 1, 1.0)) is PolicyAction.LOG_ONLY


# ----------------------------------------------------------------- clean traffic


def test_clean_request_forwarded_byte_identical() -> None:
    raw = json.dumps(messages_body("Refactor this function please.")).encode()
    verdict = inspect(make_inspector(), raw)
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.body is raw
    assert verdict.findings == []
    assert verdict.inspected


def test_count_tokens_is_inspected() -> None:
    body = messages_body(f"key {fakes.github_token()}")
    verdict = inspect(make_inspector(), body, path="/v1/messages/count_tokens")
    assert verdict.outcome is Outcome.BLOCK


def test_bodyless_get_forwarded() -> None:
    verdict = inspect(make_inspector(), b"", method="GET", path="/v1/models", content_type=None)
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.route is RouteKind.BODYLESS


# ----------------------------------------------------------------- block


def test_secret_in_tool_result_is_blocked_without_leaking_value() -> None:
    secret = fakes.aws_access_key_id()
    body = messages_body(
        [
            {
                "type": "tool_result",
                "tool_use_id": "toolu_01",
                "content": [{"type": "text", "text": f"[default]\nkey = {secret}\n"}],
            }
        ]
    )
    verdict = inspect(make_inspector(), body)
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.reason == "policy"
    assert verdict.body == b""
    assert verdict.message is not None
    assert "secrets/aws_access_key_id" in verdict.message
    assert "messages[0].content[0].content[0].text" in verdict.message
    assert secret not in verdict.message
    (finding,) = verdict.findings
    assert secret not in json.dumps(finding.as_audit())


def test_secret_in_system_prompt_tools_and_unknown_fields() -> None:
    token = fakes.github_token()
    for body in (
        messages_body("hi", system=[{"type": "text", "text": f"use {token}"}]),
        messages_body(
            "hi",
            tools=[{"name": "deploy", "description": f"token {token}", "input_schema": {}}],
        ),
        messages_body("hi", some_future_field={"nested": [f"x {token}"]}),
        messages_body(
            [{"type": "tool_use", "id": "t1", "name": "bash", "input": {"cmd": f"echo {token}"}}]
        ),
    ):
        assert inspect(make_inspector(), body).outcome is Outcome.BLOCK


def test_json_unicode_escapes_cannot_hide_secret() -> None:
    token = fakes.github_token()
    escaped = "".join(f"\\u{ord(c):04x}" for c in token)
    raw = ('{"model":"m","messages":[{"role":"user","content":"' + escaped + '"}]}').encode()
    assert inspect(make_inspector(), raw).outcome is Outcome.BLOCK


def test_block_message_truncates_long_lists() -> None:
    body = messages_body(*[f"k{i} {fakes.github_token()}" for i in range(8)])
    verdict = inspect(make_inspector(), body)
    assert verdict.message is not None
    assert "(+3 more)" in verdict.message


# ----------------------------------------------------------------- redact


def _redact_inspector(**extra: Any) -> Inspector:
    return make_inspector({**policy(secrets="REDACT", tokens="REDACT"), **extra})


def test_redaction_rewrites_only_sensitive_span() -> None:
    secret = fakes.stripe_key()
    body = messages_body(f"charge with {secret} then stop", metadata={"user_id": "u1"})
    verdict = inspect(_redact_inspector(), body)
    assert verdict.outcome is Outcome.REDACT
    sent = json.loads(verdict.body)
    text = sent["messages"][0]["content"]
    assert secret not in verdict.body.decode()
    assert text.startswith("charge with [EGRESSVEIL:stripe_secret_key:")
    assert text.endswith("] then stop")
    assert sent["metadata"] == {"user_id": "u1"}
    assert sent["model"] == body["model"]


def test_redaction_is_stable_for_prompt_caching() -> None:
    secret = fakes.github_token()
    body = messages_body(f"a {secret}", f"b {secret}")
    first = inspect(_redact_inspector(), body).body
    second = inspect(_redact_inspector(), body).body
    assert first == second
    sent = json.loads(first)
    p1 = sent["messages"][0]["content"][2:]
    p2 = sent["messages"][1]["content"][2:]
    assert p1 == p2
    assert p1.startswith(PLACEHOLDER_PREFIX)


def test_redaction_placeholder_depends_on_key() -> None:
    value = fakes.github_token()
    assert Redactor(KEY).placeholder("r", value) != Redactor(b"k" * 32).placeholder("r", value)
    with pytest.raises(ValueError, match="at least 16"):
        Redactor(b"short")


def test_redacted_output_is_not_redetected() -> None:
    body = messages_body(f"x {fakes.github_token()}")
    once = inspect(_redact_inspector(), body).body
    again = inspect(_redact_inspector(), once)
    assert again.outcome is Outcome.FORWARD


def test_mixed_block_wins_over_redact() -> None:
    body = messages_body(f"{fakes.github_token()} and {fakes.jwt()}")
    verdict = inspect(make_inspector(policy(secrets="BLOCK", tokens="REDACT")), body)
    assert verdict.outcome is Outcome.BLOCK


def test_log_only_forwards_original_but_records() -> None:
    raw = json.dumps(messages_body(f"x {fakes.github_token()}")).encode()
    verdict = inspect(make_inspector(policy(secrets="LOG_ONLY")), raw)
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.body is raw
    assert [f.action for f in verdict.findings] == [PolicyAction.LOG_ONLY]


def test_allow_drops_findings() -> None:
    verdict = inspect(make_inspector(policy(secrets="ALLOW")), messages_body(fakes.github_token()))
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.findings == []


def test_disabled_detector_does_not_run() -> None:
    verdict = inspect(
        make_inspector({"detectors": {"secrets": {"enabled": False}}}),
        messages_body(fakes.github_token()),
    )
    assert verdict.outcome is Outcome.FORWARD


# ----------------------------------------------------------------- signed & opaque


def test_signature_values_are_not_scanned() -> None:
    body = messages_body(
        [{"type": "thinking", "thinking": "plan", "signature": fakes.github_token()}]
    )
    assert inspect(make_inspector(), body).outcome is Outcome.FORWARD


@pytest.mark.parametrize("policy_action", ["REDACT", "BLOCK"])
def test_signed_thinking_is_recorded_not_modified_or_blocked(policy_action: str) -> None:
    raw = json.dumps(
        messages_body(
            [{"type": "thinking", "thinking": f"found {fakes.github_token()}", "signature": "s"}]
        )
    ).encode()
    verdict = inspect(make_inspector(policy(secrets=policy_action)), raw)
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.body is raw  # signature stays valid
    (finding,) = verdict.findings
    assert finding.signed
    assert finding.action is PolicyAction.LOG_ONLY
    assert finding.as_audit()["signed"] is True


def test_redacted_thinking_is_skipped() -> None:
    body = messages_body([{"type": "redacted_thinking", "data": fakes.github_token()}])
    assert inspect(make_inspector(), body).outcome is Outcome.FORWARD


def _image_body() -> dict[str, Any]:
    return messages_body(
        [
            {
                "type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"},
            },
            {"type": "text", "text": "what is this?"},
        ]
    )


def test_opaque_content_blocked_in_strict_mode() -> None:
    verdict = inspect(make_inspector(), _image_body())
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.reason == "opaque_content"
    assert verdict.message is not None
    assert "allow_opaque_content" in verdict.message


def test_opaque_content_allowed_by_opt_in() -> None:
    verdict = inspect(make_inspector({"gateway": {"allow_opaque_content": True}}), _image_body())
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.opaque[0].kind == "image/png"
    assert verdict.reason == "opaque_content_forwarded"


def test_opaque_with_secret_text_still_blocked() -> None:
    body = _image_body()
    body["messages"][0]["content"][1]["text"] = fakes.github_token()
    verdict = inspect(make_inspector({"gateway": {"allow_opaque_content": True}}), body)
    assert verdict.outcome is Outcome.BLOCK


def test_url_image_source_is_scanned_not_opaque() -> None:
    body = messages_body(
        [{"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}}]
    )
    assert inspect(make_inspector(), body).outcome is Outcome.FORWARD


# ----------------------------------------------------------------- query string


def test_query_string_secret_blocks_even_with_redact_policy() -> None:
    verdict = inspect(
        _redact_inspector(),
        messages_body("hi"),
        query=f"beta=true&key={fakes.github_token()}",
    )
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.findings[0].location == URL_LOCATION
    assert verdict.findings[0].escalated


def test_normal_query_string_is_fine() -> None:
    assert inspect(make_inspector(), messages_body("hi"), query="beta=true").outcome is (
        Outcome.FORWARD
    )


# ----------------------------------------------------------------- fail closed


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"path": "/v1/files"}, "unsupported_route"),
        ({"content_type": "text/plain"}, "unsupported_content_type"),
        ({"content_type": None}, "unsupported_content_type"),
        ({"content_encoding": "gzip"}, "unsupported_content_encoding"),
    ],
)
def test_strict_mode_fails_closed(kwargs: dict[str, Any], reason: str) -> None:
    verdict = inspect(make_inspector(), messages_body("hi"), **kwargs)
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.reason == reason
    assert not verdict.inspected


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"{not json", "invalid_json"),
        (b"[1, 2, 3]", "invalid_json"),
        (b"\xff\xfe", "invalid_json"),
        (b'{"messages": NaN}', "invalid_json"),
        (b'{"model": "a", "model": "b"}', "duplicate_key"),
        (b'{"a":' * 100 + b"1" + b"}" * 100, "nesting_too_deep"),
        # Object root so the result is the same whether the platform's json
        # decoder raises RecursionError (Windows) or parses it (Linux/macOS)
        # and the walker's depth limit rejects it.
        (b'{"a":' + b"[" * 5000 + b"]" * 5000 + b"}", "nesting_too_deep"),
    ],
)
def test_malformed_bodies_fail_closed(raw: bytes, reason: str) -> None:
    verdict = inspect(make_inspector(), raw)
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.reason == reason


def test_permissive_mode_forwards_uninspectable_unchanged() -> None:
    raw = b"{not json"
    verdict = inspect(make_inspector({"gateway": {"mode": "permissive"}}), raw)
    assert verdict.outcome is Outcome.FORWARD
    assert verdict.body is raw
    assert verdict.reason == "invalid_json"
    assert not verdict.inspected


def test_permissive_mode_still_enforces_policy() -> None:
    verdict = inspect(
        make_inspector({"gateway": {"mode": "permissive"}}), messages_body(fakes.github_token())
    )
    assert verdict.outcome is Outcome.BLOCK


class _ExplodingDetector:
    category = "secrets"

    def scan(self, text: str) -> list[Finding]:
        raise RuntimeError("boom")


@pytest.mark.parametrize(
    ("mode", "outcome"),
    [(GatewayMode.STRICT, Outcome.BLOCK), (GatewayMode.PERMISSIVE, Outcome.FORWARD)],
)
def test_detector_crash_respects_mode(mode: GatewayMode, outcome: Outcome) -> None:
    from egressveil.audit import AuditLogger

    inspector = Inspector(
        detectors=[_ExplodingDetector()],
        engine=PolicyEngine(make_config().policy),
        redactor=Redactor(KEY),
        audit=AuditLogger(None, KEY),
        mode=mode,
        allow_opaque_content=False,
    )
    verdict = inspect(inspector, messages_body("hi"))
    assert verdict.outcome is outcome
    assert verdict.reason == "detector_error"
