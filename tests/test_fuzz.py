"""Property-based fuzzing of the parser, inspector and response scanner.

Invariants, for any input:
* inspection never raises; it returns FORWARD, REDACT or BLOCK;
* FORWARD sends the original bytes; BLOCK sends nothing;
* REDACT sends valid JSON in which no planted sensitive value survives;
* block messages and audit digests never contain a planted value;
* the response scanner never raises on arbitrary chunking.
"""

from __future__ import annotations

import json
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from egressveil.inspection import Outcome
from egressveil.providers import anthropic, openai
from egressveil.responses import ResponseScanner
from tests import fakes
from tests.helpers import inspect, make_inspector

SENSITIVE = [
    fakes.github_token(),
    fakes.aws_access_key_id(),
    fakes.stripe_key(),
    fakes.jwt(),
    "jane.doe@acme-corp.io",
    "api.billing.internal",
]

REDACT_ALL = make_inspector({"policy": {"pack": "redact"}})
DEFAULT = make_inspector()
FUZZ = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])

texts = st.one_of(
    st.text(max_size=40),
    st.sampled_from(SENSITIVE),
    st.builds(
        lambda a, s, b: f"{a} {s} {b}",
        st.text(max_size=10),
        st.sampled_from(SENSITIVE),
        st.text(max_size=10),
    ),
    st.sampled_from(["data:image/png;base64,iVBOR", "thinking", "tool_result", "image"]),
)
keys = st.one_of(
    st.sampled_from(
        [
            "type",
            "text",
            "content",
            "source",
            "signature",
            "data",
            "input",
            "messages",
            "system",
            "role",
            "id",
            "delta",
            "encrypted_content",
        ]
    ),
    st.text(max_size=8),
)
json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | texts,
    lambda children: st.lists(children, max_size=5) | st.dictionaries(keys, children, max_size=5),
    max_leaves=40,
)
bodies = st.dictionaries(keys, json_values, max_size=6)
adapters = st.sampled_from(
    [(anthropic.ADAPTER, "/v1/messages"), (openai.ADAPTER, "/v1/chat/completions")]
)


def planted_in(raw: bytes) -> list[str]:
    text = raw.decode("utf-8", errors="replace")
    return [s for s in SENSITIVE if s in text]


@FUZZ
@given(body=bodies, target=adapters)
def test_inspection_invariants(body: dict[str, Any], target: Any) -> None:
    adapter, path = target
    raw = json.dumps(body).encode()
    for inspector in (REDACT_ALL, DEFAULT):
        verdict = inspect(inspector, raw, path=path, adapter=adapter)
        assert verdict.outcome in set(Outcome)
        if verdict.outcome is Outcome.FORWARD:
            assert verdict.body is raw
        elif verdict.outcome is Outcome.BLOCK:
            assert verdict.body == b""
            assert not [s for s in SENSITIVE if s in (verdict.message or "")]
        else:
            redacted = json.loads(verdict.body)
            assert isinstance(redacted, dict)
            assert set(redacted) == set(body)  # structure preserved
        for finding in verdict.findings:
            assert not [s for s in SENSITIVE if s in json.dumps(finding.as_audit())]


@FUZZ
@given(body=bodies)
def test_redact_pack_never_forwards_planted_values_from_inspectable_fields(
    body: dict[str, Any],
) -> None:
    raw = json.dumps(body).encode()
    verdict = inspect(REDACT_ALL, raw)
    if verdict.outcome is Outcome.REDACT:
        leftover = planted_in(verdict.body)
        # Only values inside skipped/opaque/signed places may remain.
        sent = json.loads(verdict.body)
        for value in leftover:
            assert _only_in_uninspected(sent, value), value


def _only_in_uninspected(
    node: Any, value: str, key: str = "", signed: bool = False, parent: Any = None
) -> bool:
    """True if every occurrence sits where the walker deliberately doesn't look."""
    skip = {"model", "type", "role", "id", "tool_use_id", "media_type", "signature"}
    if isinstance(node, dict):
        child_signed = signed or node.get("type") == "thinking"
        return all(_only_in_uninspected(v, value, k, child_signed, node) for k, v in node.items())
    if isinstance(node, list):
        return all(_only_in_uninspected(v, value, key, signed, parent) for v in node)
    if isinstance(node, str) and value in node:
        blob = (
            key == "data"
            and isinstance(parent, dict)
            and (parent.get("type") in {"base64", "redacted_thinking"})
        )
        return key in skip or signed or blob or node.startswith("data:")
    return True


@FUZZ
@given(
    raw=st.binary(max_size=300),
    target=adapters,
    ctype=st.sampled_from(["application/json", "text/plain", None]),
    enc=st.sampled_from([None, "identity", "gzip"]),
)
def test_arbitrary_bytes_never_crash(
    raw: bytes, target: Any, ctype: str | None, enc: str | None
) -> None:
    adapter, path = target
    verdict = inspect(
        DEFAULT, raw, path=path, adapter=adapter, content_type=ctype, content_encoding=enc
    )
    assert verdict.outcome in {Outcome.FORWARD, Outcome.BLOCK, Outcome.REDACT}
    if verdict.outcome is Outcome.FORWARD:
        assert verdict.body is raw


@FUZZ
@given(
    chunks=st.lists(st.binary(max_size=64), max_size=20),
    ctype=st.sampled_from(["text/event-stream", "application/json", "text/plain"]),
)
def test_response_scanner_never_crashes(chunks: list[bytes], ctype: str) -> None:
    scanner = ResponseScanner(DEFAULT, ctype, 10_000)
    for chunk in chunks:
        scanner.feed(chunk)
    findings = scanner.finish()
    assert isinstance(findings, list)


@FUZZ
@given(
    secret=st.sampled_from(SENSITIVE[:4]),
    cut=st.integers(min_value=1, max_value=20),
    step=st.integers(min_value=1, max_value=50),
)
def test_split_secret_in_stream_always_found(secret: str, cut: int, step: int) -> None:
    cut = min(cut, len(secret) - 1)
    events = [{"delta": {"text": secret[:cut]}}, {"delta": {"text": secret[cut:]}}]
    data = b"".join(f"data: {json.dumps(e)}\n\n".encode() for e in events)
    scanner = ResponseScanner(DEFAULT, "text/event-stream", 10**6)
    for i in range(0, len(data), step):
        scanner.feed(data[i : i + step])
    assert scanner.finish(), "split value was not reassembled"


# ----------------------------------------------------------------- regressions found by fuzzing


def test_text_nested_under_signature_is_inspected() -> None:
    token = fakes.github_token()
    body = {"text": "hi", "signature": {"text": token}}
    assert inspect(DEFAULT, body).outcome is Outcome.BLOCK


def test_extra_fields_in_redacted_thinking_are_inspected() -> None:
    token = fakes.github_token()
    body = {
        "messages": [
            {
                "role": "assistant",
                "content": [{"type": "redacted_thinking", "data": token, "note": token}],
            }
        ]
    }
    verdict = inspect(DEFAULT, body)
    assert verdict.outcome is Outcome.BLOCK
    assert {f.location for f in verdict.findings} == {"messages[0].content[0].note"}


def test_extra_fields_beside_base64_data_are_inspected() -> None:
    token = fakes.github_token()
    allow = make_inspector({"gateway": {"allow_opaque_content": True}})
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": "iVBOR",
                            "note": token,
                        },
                    }
                ],
            }
        ]
    }
    verdict = inspect(allow, body)
    assert verdict.outcome is Outcome.BLOCK
    assert verdict.opaque[0].location == "messages[0].content[0].source.data"


def test_encrypted_content_object_is_inspected() -> None:
    body = {
        "model": "m",
        "input": [{"type": "reasoning", "encrypted_content": {"t": fakes.github_token()}}],
    }
    verdict = inspect(DEFAULT, body, path="/v1/responses", adapter=openai.ADAPTER)
    assert verdict.outcome is Outcome.BLOCK
