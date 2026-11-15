from __future__ import annotations

from collections.abc import Callable

import pytest

from egressveil.detectors import Finding, build_detectors, merge_spans
from egressveil.detectors.patterns import (
    SECRET_RULES,
    TOKEN_RULES,
    PatternDetector,
    looks_like_placeholder,
    shannon_entropy,
)
from tests import fakes

secrets_detector = PatternDetector("secrets", SECRET_RULES)
tokens_detector = PatternDetector("tokens", TOKEN_RULES)


def rules_in(text: str) -> set[str]:
    return {f.rule_id for d in (secrets_detector, tokens_detector) for f in d.scan(text)}


def spans_for(text: str, rule_id: str) -> list[str]:
    return [
        text[f.start : f.end]
        for d in (secrets_detector, tokens_detector)
        for f in d.scan(text)
        if f.rule_id == rule_id
    ]


POSITIVE: list[tuple[str, Callable[[], str], Callable[[str], str]]] = [
    ("anthropic_api_key", fakes.anthropic_key, lambda v: f"ANTHROPIC_KEY used: {v}"),
    ("openai_api_key", fakes.openai_key, lambda v: f"client = OpenAI(api_key={v})"),
    ("aws_access_key_id", fakes.aws_access_key_id, lambda v: f"[default]\nkey={v}\n"),
    (
        "aws_secret_access_key",
        fakes.aws_secret,
        lambda v: f"aws_secret_access_key = {v}\n",
    ),
    ("github_token", fakes.github_token, lambda v: f"git clone https://{v}@github.com/o/r"),
    ("github_fine_grained_pat", fakes.github_fine_grained, lambda v: f"GH={v}"),
    ("gitlab_token", fakes.gitlab_token, lambda v: f"token: {v}"),
    ("slack_token", fakes.slack_token, lambda v: f"SLACK={v}"),
    ("slack_webhook", fakes.slack_webhook, lambda v: f"post to {v} now"),
    ("stripe_secret_key", fakes.stripe_key, lambda v: f"stripe.api_key = '{v}'"),
    ("google_api_key", fakes.google_api_key, lambda v: f"?key={v}&q=1"),
    ("npm_token", fakes.npm_token, lambda v: f"//registry.npmjs.org/:_authToken={v}"),
    ("huggingface_token", fakes.huggingface_token, lambda v: f"HF={v}"),
    ("private_key", fakes.private_key_block, lambda v: f"id_rsa:\n{v}\n"),
    (
        "url_credentials",
        fakes.db_password,
        lambda v: f"DATABASE_URL=postgres://app:{v}@db.internal:5432/app",
    ),
    (
        "generic_secret_assignment",
        fakes.db_password,
        lambda v: f'config = {{"client_secret": "{v}"}}',
    ),
    ("env_file_assignment", fakes.db_password, lambda v: f"export SERVICE_API_KEY={v}\n"),
    ("jwt", fakes.jwt, lambda v: f"cookie: session={v};"),
    ("bearer_token", lambda: "Q9" + fakes.rand(30), lambda v: f"Authorization: Bearer {v}"),
]


@pytest.mark.parametrize(("rule_id", "make", "wrap"), POSITIVE, ids=[p[0] for p in POSITIVE])
def test_rule_detects_and_spans_exact_value(
    rule_id: str, make: Callable[[], str], wrap: Callable[[str], str]
) -> None:
    value = make()
    text = wrap(value)
    assert rule_id in rules_in(text)
    spans = spans_for(text, rule_id)
    assert value in spans or any(value in s for s in spans)


def test_private_key_without_end_marker_covers_body() -> None:
    block = fakes.private_key_block()
    truncated = block.rsplit("-----END", 1)[0]
    (span,) = spans_for(truncated, "private_key")
    assert len(span) > len(truncated) * 0.9


@pytest.mark.parametrize(
    "text",
    [
        "password = request.form['password']",
        '"max_tokens": 4096, "temperature": 0.2',
        'token = "${GITHUB_TOKEN}"',
        "api_key = 'your-api-key-here-1234'",
        "postgres://user:password@localhost:5432/db",
        "postgres://user:${DB_PASSWORD}@localhost:5432/db",
        "commit 3f9a1c2b7d4e5f60718293a4b5c6d7e8f9012345",
        "id: 123e4567-e89b-12d3-a456-426614174000",
        "Authorization: Bearer <token>",
        "secret_name = 'projects/acme/secrets/db'",
        "the risk-assessment-framework-for-engineering-teams-2024 doc",
        "[EGRESSVEIL:github_token:1234abcd] was redacted",
        "def tokenize(text): return text.split()",
        'PASSWORD_MIN_LENGTH=12\nSECRET_KEY=""\n',
        # Regressions found by running `egressveil scan` on this repository:
        "KEY = secrets.token_bytes(32)",
        "API_KEY = os.environ.get('ANTHROPIC_API_KEY2')",
        "SECRET_KEY=get_secret(name='app-2024')",
        'url = f"postgres://{user}:{password}@{host}:5432/db"',
        'dsn = "mysql://%s:%s@%s/db" % (u, p, h)',
    ],
)
def test_common_code_is_not_flagged(text: str) -> None:
    assert rules_in(text) == set()


def test_env_assignment_allows_trailing_comment() -> None:
    value = fakes.db_password()
    assert "env_file_assignment" in rules_in(f"DB_PASSWORD={value}  # rotate monthly\n")


def test_aws_documentation_example_key_ignored() -> None:
    assert rules_in(f"key = {fakes.aws_doc_example_key()}") == set()


def test_findings_never_contain_text() -> None:
    value = fakes.github_token()
    (finding,) = secrets_detector.scan(f"x {value} y")
    assert value not in repr(finding)
    assert not any(isinstance(v, str) and value in v for v in finding.__slots__)


def test_entropy_and_placeholders() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy(fakes.rand(32)) > 4.0
    assert looks_like_placeholder("<your token>")
    assert looks_like_placeholder("xxxxxxxxxxxx")
    assert not looks_like_placeholder(fakes.rand(20))


def test_merge_spans_overlap_keeps_best() -> None:
    a = Finding("tokens", "bearer_token", 10, 40, 0.7)
    b = Finding("tokens", "jwt", 12, 50, 0.95)
    c = Finding("secrets", "x", 60, 70, 0.9)
    merged = merge_spans([c, a, b])
    assert [(s, e) for s, e, _ in merged] == [(10, 50), (60, 70)]
    assert merged[0][2].rule_id == "jwt"


def test_build_detectors_only_implemented() -> None:
    cats = {d.category for d in build_detectors(["secrets", "tokens", "pii"])}
    assert cats == {"secrets", "tokens"}
    assert build_detectors([]) == []


def test_large_input_scans_quickly() -> None:
    import time

    blob = ("lorem ipsum dolor sit amet " * 40_000) + fakes.github_token()
    started = time.perf_counter()
    found = rules_in(blob)
    assert "github_token" in found
    assert time.perf_counter() - started < 5.0
