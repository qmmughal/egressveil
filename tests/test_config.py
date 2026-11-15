from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from egressveil.config import (
    CONFIG_ENV_VAR,
    MAX_CONFIG_FILE_BYTES,
    IssueLevel,
    ValidationIssue,
    discover_config,
    is_loopback_host,
    load_config,
    parse_config,
)
from egressveil.policy import GatewayMode, PolicyAction
from tests.conftest import FAKE_CREDENTIAL


def _errors(issues: list[ValidationIssue]) -> list[str]:
    return [i.path for i in issues if i.level is IssueLevel.ERROR]


def _warnings(issues: list[ValidationIssue]) -> list[str]:
    return [i.path for i in issues if i.level is IssueLevel.WARNING]


# ----------------------------------------------------------------- defaults


def test_defaults_are_secure() -> None:
    config, issues = parse_config({})
    assert config is not None
    assert issues == []
    assert config.gateway.listen_host == "127.0.0.1"
    assert config.gateway.mode is GatewayMode.STRICT
    assert config.audit.include_raw_values is False
    assert config.telemetry_enabled is False
    assert config.providers["anthropic"].enabled
    assert not config.providers["openai"].enabled
    actions = {r.detector: r.action for r in config.policy.rules}
    assert actions["secrets"] is PolicyAction.BLOCK
    assert actions["tokens"] is PolicyAction.BLOCK


def test_example_config_is_valid(example_config_path: Path) -> None:
    result = load_config(example_config_path)
    assert result.ok, [str(i) for i in result.issues]
    assert result.errors == []
    assert result.config is not None
    assert result.config.detectors["internal_hostnames"].internal_domains


# ----------------------------------------------------------------- gateway


@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "::1", "localhost", "LOCALHOST"])
def test_loopback_hosts_accepted(host: str) -> None:
    assert is_loopback_host(host)
    config, issues = parse_config({"gateway": {"listen_host": host}})
    assert config is not None
    assert _errors(issues) == []


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com", "::"])  # noqa: S104
def test_non_loopback_host_rejected_by_default(host: str) -> None:
    config, issues = parse_config({"gateway": {"listen_host": host}})
    assert config is None
    assert "gateway.listen_host" in _errors(issues)


def test_non_loopback_host_requires_explicit_opt_in() -> None:
    config, issues = parse_config(
        {"gateway": {"listen_host": "0.0.0.0", "allow_non_loopback": True}}  # noqa: S104
    )
    assert config is not None
    assert "gateway.listen_host" in _warnings(issues)


@pytest.mark.parametrize("port", [0, 70000, "8080", True, 1.5])
def test_invalid_port_rejected(port: object) -> None:
    config, issues = parse_config({"gateway": {"listen_port": port}})
    assert config is None
    assert "gateway.listen_port" in _errors(issues)


def test_body_limit_bounds() -> None:
    config, issues = parse_config({"gateway": {"max_request_body_bytes": 10}})
    assert config is None
    assert "gateway.max_request_body_bytes" in _errors(issues)


def test_permissive_mode_warns() -> None:
    config, issues = parse_config({"gateway": {"mode": "permissive"}})
    assert config is not None
    assert config.gateway.mode is GatewayMode.PERMISSIVE
    assert "gateway.mode" in _warnings(issues)


def test_invalid_mode_rejected() -> None:
    config, issues = parse_config({"gateway": {"mode": "yolo"}})
    assert config is None
    assert "gateway.mode" in _errors(issues)


# ----------------------------------------------------------------- providers


def test_http_upstream_rejected() -> None:
    config, issues = parse_config(
        {"providers": {"anthropic": {"upstream_url": "http://api.anthropic.com"}}}
    )
    assert config is None
    assert "providers.anthropic.upstream_url" in _errors(issues)


def test_unlisted_upstream_rejected_without_opt_in() -> None:
    raw = {"providers": {"anthropic": {"upstream_url": "https://llm.example.net"}}}
    config, issues = parse_config(raw)
    assert config is None
    assert "providers.anthropic.upstream_url" in _errors(issues)

    raw["providers"]["anthropic"]["allow_custom_upstream"] = True  # type: ignore[index]
    config, issues = parse_config(raw)
    assert config is not None
    assert "providers.anthropic.upstream_url" in _warnings(issues)


def test_credentials_in_upstream_url_rejected() -> None:
    url = "https://user:pw@api.anthropic.com"
    config, issues = parse_config({"providers": {"anthropic": {"upstream_url": url}}})
    assert config is None
    assert all("pw" not in str(i) for i in issues)


def test_unknown_provider_rejected() -> None:
    config, issues = parse_config({"providers": {"mystery": {"enabled": True}}})
    assert config is None
    assert "providers" in _errors(issues)


def test_no_enabled_provider_warns() -> None:
    config, issues = parse_config({"providers": {"anthropic": {"enabled": False}}})
    assert config is not None
    assert "providers" in _warnings(issues)


def test_upstream_origin_hides_path() -> None:
    config, _ = parse_config(
        {"providers": {"anthropic": {"upstream_url": "https://api.anthropic.com/v1/"}}}
    )
    assert config is not None
    assert config.providers["anthropic"].upstream_origin == "https://api.anthropic.com"


# ----------------------------------------------------------------- policy & detectors


def test_policy_rules_parsed() -> None:
    config, issues = parse_config(
        {
            "policy": {
                "default_action": "log_only",
                "rules": [{"detector": "pii", "action": "BLOCK"}],
            }
        }
    )
    assert config is not None, issues
    assert config.policy.default_action is PolicyAction.LOG_ONLY
    assert config.policy.rules[0].action is PolicyAction.BLOCK


@pytest.mark.parametrize(
    "rules",
    [
        [{"detector": "nope", "action": "BLOCK"}],
        [{"detector": "pii", "action": "DESTROY"}],
        [{"detector": "pii"}],
        [{"detector": "pii", "action": "BLOCK"}, {"detector": "pii", "action": "ALLOW"}],
        "not-a-list",
    ],
)
def test_invalid_policy_rules(rules: object) -> None:
    config, issues = parse_config({"policy": {"rules": rules}})
    assert config is None
    assert _errors(issues)


def test_allowing_secrets_warns() -> None:
    config, issues = parse_config(
        {"policy": {"rules": [{"detector": "secrets", "action": "ALLOW"}]}}
    )
    assert config is not None
    assert "policy.rules[0].action" in _warnings(issues)


def test_internal_domains_validated() -> None:
    config, issues = parse_config(
        {
            "detectors": {
                "internal_hostnames": {"internal_domains": ["corp.example.com", ".INT.example"]}
            }
        }
    )
    assert config is not None, issues
    assert config.detectors["internal_hostnames"].internal_domains == (
        "corp.example.com",
        "int.example",
    )

    config, issues = parse_config(
        {"detectors": {"internal_hostnames": {"internal_domains": ["not a domain"]}}}
    )
    assert config is None


def test_disabling_secret_detector_warns() -> None:
    config, issues = parse_config({"detectors": {"secrets": {"enabled": False}}})
    assert config is not None
    assert "detectors.secrets" in _warnings(issues)


# ----------------------------------------------------------------- audit & telemetry


def test_raw_value_audit_logging_rejected() -> None:
    config, issues = parse_config({"audit": {"include_raw_values": True}})
    assert config is None
    assert "audit.include_raw_values" in _errors(issues)


def test_telemetry_cannot_be_enabled() -> None:
    config, issues = parse_config({"telemetry": {"enabled": True}})
    assert config is None
    assert "telemetry.enabled" in _errors(issues)


# ----------------------------------------------------------------- schema strictness & secrecy


def test_unknown_keys_rejected() -> None:
    config, issues = parse_config({"gateway": {"listen_hots": "127.0.0.1"}})
    assert config is None
    assert any("listen_hots" in str(i) for i in issues)


def test_unknown_key_with_weird_content_is_not_echoed() -> None:
    config, issues = parse_config({"gateway": {"has spaces and $ymbols": 1}})
    assert config is None
    assert all("$ymbols" not in str(i) for i in issues)


def test_wrong_schema_version_rejected() -> None:
    config, issues = parse_config({"version": 2})
    assert config is None
    assert "version" in _errors(issues)


def test_root_must_be_mapping() -> None:
    config, issues = parse_config(["a", "list"])
    assert config is None
    assert _errors(issues)


def test_embedded_credential_rejected_and_not_echoed() -> None:
    config, issues = parse_config({"audit": {"path": FAKE_CREDENTIAL}})
    assert config is None
    assert "audit.path" in _errors(issues)
    assert all(FAKE_CREDENTIAL not in str(i) for i in issues)


def test_type_errors_do_not_echo_values() -> None:
    config, issues = parse_config({"gateway": {"listen_port": "super-secret-value"}})
    assert config is None
    assert all("super-secret-value" not in str(i) for i in issues)


# ----------------------------------------------------------------- file loading & discovery


def test_load_missing_explicit_file(tmp_path: Path) -> None:
    result = load_config(tmp_path / "missing.yaml")
    assert not result.ok
    assert result.source.origin == "--config"


def test_load_empty_file_uses_defaults(write_config: Callable[[str], Path]) -> None:
    result = load_config(write_config(""))
    assert result.ok
    assert result.issues == []


def test_invalid_yaml_reports_position_only(write_config: Callable[[str], Path]) -> None:
    path = write_config(f"gateway: [unclosed\n  token: {FAKE_CREDENTIAL}\n")
    result = load_config(path)
    assert not result.ok
    message = str(result.errors[0])
    assert "invalid YAML" in message
    assert FAKE_CREDENTIAL not in message


def test_oversized_file_rejected(write_config: Callable[[str], Path]) -> None:
    path = write_config("#" * (MAX_CONFIG_FILE_BYTES + 1))
    result = load_config(path)
    assert not result.ok
    assert "exceeds" in str(result.errors[0])


def test_non_utf8_file_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"\xff\xfe\x00bad")
    result = load_config(path)
    assert not result.ok


def test_yaml_tags_are_not_executed(write_config: Callable[[str], Path]) -> None:
    path = write_config("gateway: !!python/object/apply:os.system ['echo pwned']\n")
    result = load_config(path)
    assert not result.ok


def test_discovery_order(
    tmp_path: Path, isolated_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert discover_config().origin == "defaults"

    local = isolated_env / "egressveil.yaml"
    local.write_text("version: 1\n", encoding="utf-8")
    assert discover_config().origin == "working directory"

    env_file = tmp_path / "from-env.yaml"
    env_file.write_text("version: 1\n", encoding="utf-8")
    monkeypatch.setenv(CONFIG_ENV_VAR, str(env_file))
    assert discover_config().path == env_file

    explicit = tmp_path / "explicit.yaml"
    assert discover_config(explicit).path == explicit
