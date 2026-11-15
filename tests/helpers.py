from __future__ import annotations

import json
import secrets
from dataclasses import replace
from typing import Any

from egressveil.audit import AuditLogger
from egressveil.config import EgressVeilConfig, parse_config
from egressveil.inspection import Inspector, Verdict
from egressveil.providers import anthropic
from egressveil.providers.base import ProviderAdapter
from egressveil.redactor import Redactor

KEY = secrets.token_bytes(32)


def make_config(raw: dict[str, Any] | None = None) -> EgressVeilConfig:
    config, issues = parse_config(raw or {})
    assert config is not None, [str(i) for i in issues]
    return config


def make_inspector(raw: dict[str, Any] | None = None, *, key: bytes = KEY) -> Inspector:
    return Inspector.from_config(
        make_config(raw), redactor=Redactor(key), audit=AuditLogger(None, key)
    )


def policy(**actions: str) -> dict[str, Any]:
    return {"policy": {"rules": [{"detector": d, "action": a} for d, a in actions.items()]}}


def messages_body(*contents: Any, **extra: Any) -> dict[str, Any]:
    return {
        "model": "claude-sonnet-5-5",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": c} for c in contents],
        **extra,
    }


def inspect(
    inspector: Inspector,
    body: dict[str, Any] | bytes,
    *,
    method: str = "POST",
    path: str = "/v1/messages",
    query: str = "",
    content_type: str | None = "application/json",
    content_encoding: str | None = None,
    adapter: ProviderAdapter = anthropic.ADAPTER,
) -> Verdict:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return inspector.inspect_request(
        adapter=adapter,
        method=method,
        path=path,
        query=query,
        content_type=content_type,
        content_encoding=content_encoding,
        body=raw,
    )


def with_upstream(cfg: EgressVeilConfig, url: str, provider: str = "anthropic") -> EgressVeilConfig:
    providers = dict(cfg.providers)
    providers[provider] = replace(providers[provider], upstream_url=url)
    return replace(cfg, providers=providers)
