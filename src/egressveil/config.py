"""Configuration loading and validation.

Design rules for this module:

* The schema is strict. Unknown keys are errors so typos never silently
  weaken a security setting.
* Validation messages never echo configuration *values*. They refer to the
  location of a problem (``gateway.listen_port``) and the expected type, so
  that ``egressveil config validate`` output is always safe to paste into an
  issue or a chat window.
* Insecure settings are either rejected outright (raw-value audit logging,
  plain-HTTP upstreams, credentials in the file) or require an explicit,
  separately named opt-in that produces a warning.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, TypeVar
from urllib.parse import urlsplit

import yaml

from egressveil.detectors import DETECTOR_CATEGORIES
from egressveil.policy import GatewayMode, PolicyAction
from egressveil.providers import KNOWN_PROVIDERS

__all__ = [
    "CONFIG_ENV_VAR",
    "CONFIG_FILENAME",
    "MAX_CONFIG_FILE_BYTES",
    "AuditConfig",
    "ConfigSource",
    "DetectorConfig",
    "EgressVeilConfig",
    "GatewayConfig",
    "IssueLevel",
    "LoadResult",
    "PolicyConfig",
    "PolicyRule",
    "ProviderConfig",
    "ValidationIssue",
    "discover_config",
    "load_config",
    "parse_config",
    "user_config_dir",
]

CONFIG_ENV_VAR: Final = "EGRESSVEIL_CONFIG"
CONFIG_FILENAME: Final = "egressveil.yaml"
SCHEMA_VERSION: Final = 1
MAX_CONFIG_FILE_BYTES: Final = 1024 * 1024  # 1 MiB

KIB: Final = 1024
MIB: Final = 1024 * KIB

LOOPBACK_NAMES: Final = frozenset({"localhost"})

# Well-known credential shapes. Used only to *refuse* config files that embed
# credentials; matched text is never printed.
_CREDENTIAL_PATTERN: Final = re.compile(
    r"(sk-[A-Za-z0-9_\-]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
)

_SAFE_KEY: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")
_DOMAIN: Final = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
)


# --------------------------------------------------------------------------- issues


class IssueLevel(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    level: IssueLevel
    path: str
    message: str

    def __str__(self) -> str:
        where = self.path or "<root>"
        return f"{self.level.value}: {where}: {self.message}"


# --------------------------------------------------------------------------- model


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8787
    mode: GatewayMode = GatewayMode.STRICT
    allow_non_loopback: bool = False
    max_request_body_bytes: int = 16 * MIB
    max_stream_buffer_bytes: int = 1 * MIB


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    name: str
    enabled: bool
    upstream_url: str
    allow_custom_upstream: bool = False

    @property
    def upstream_origin(self) -> str:
        """``scheme://host[:port]`` - safe to display."""
        parts = urlsplit(self.upstream_url)
        return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    detector: str
    action: PolicyAction


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    default_action: PolicyAction = PolicyAction.REDACT
    rules: tuple[PolicyRule, ...] = (
        PolicyRule("secrets", PolicyAction.BLOCK),
        PolicyRule("tokens", PolicyAction.BLOCK),
        PolicyRule("pii", PolicyAction.REDACT),
        PolicyRule("internal_hostnames", PolicyAction.REDACT),
    )


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    name: str
    enabled: bool = True
    internal_domains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditConfig:
    enabled: bool = True
    path: str = "~/.egressveil/audit.jsonl"
    include_raw_values: bool = False

    @property
    def resolved_path(self) -> Path:
        return Path(self.path).expanduser()


def _default_providers() -> dict[str, ProviderConfig]:
    return {
        name: ProviderConfig(
            name=name,
            enabled=(name == "anthropic"),
            upstream_url=spec.default_upstream_url,
        )
        for name, spec in KNOWN_PROVIDERS.items()
    }


def _default_detectors() -> dict[str, DetectorConfig]:
    return {name: DetectorConfig(name=name) for name in sorted(DETECTOR_CATEGORIES)}


@dataclass(frozen=True, slots=True)
class EgressVeilConfig:
    version: int = SCHEMA_VERSION
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    providers: dict[str, ProviderConfig] = field(default_factory=_default_providers)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    detectors: dict[str, DetectorConfig] = field(default_factory=_default_detectors)
    audit: AuditConfig = field(default_factory=AuditConfig)
    telemetry_enabled: bool = False

    def summary(self) -> list[tuple[str, str]]:
        """Human-readable, secret-free view of the effective configuration."""
        g = self.gateway
        rows: list[tuple[str, str]] = [
            ("gateway.listen", f"{g.listen_host}:{g.listen_port}"),
            ("gateway.mode", g.mode.value),
            ("gateway.max_request_body_bytes", str(g.max_request_body_bytes)),
            ("gateway.max_stream_buffer_bytes", str(g.max_stream_buffer_bytes)),
        ]
        for name, p in sorted(self.providers.items()):
            state = "enabled" if p.enabled else "disabled"
            rows.append((f"providers.{name}", f"{state} -> {p.upstream_origin}"))
        rows.append(("policy.default_action", self.policy.default_action.value))
        rows.extend((f"policy.rule[{r.detector}]", r.action.value) for r in self.policy.rules)
        for name, d in sorted(self.detectors.items()):
            extra = f" ({len(d.internal_domains)} internal domains)" if d.internal_domains else ""
            rows.append((f"detectors.{name}", ("enabled" if d.enabled else "disabled") + extra))
        rows.append(("audit.enabled", str(self.audit.enabled).lower()))
        rows.append(("telemetry.enabled", str(self.telemetry_enabled).lower()))
        return rows


# --------------------------------------------------------------------------- validation

T = TypeVar("T")
E = TypeVar("E", bound=StrEnum)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _describe_key(key: object) -> str:
    """Render a mapping key for an error message without leaking content."""
    if isinstance(key, str) and _SAFE_KEY.match(key):
        return repr(key)
    return "<non-identifier key>"


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    return {bool: "boolean", int: "integer", str: "string", list: "list", dict: "mapping"}.get(
        type(value), type(value).__name__
    )


class _Validator:
    def __init__(self) -> None:
        self.issues: list[ValidationIssue] = []

    def error(self, path: str, message: str) -> None:
        self.issues.append(ValidationIssue(IssueLevel.ERROR, path, message))

    def warn(self, path: str, message: str) -> None:
        self.issues.append(ValidationIssue(IssueLevel.WARNING, path, message))

    @property
    def ok(self) -> bool:
        return not any(i.level is IssueLevel.ERROR for i in self.issues)

    # -- structural helpers ---------------------------------------------------

    def mapping(self, value: object, path: str, allowed: frozenset[str]) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            self.error(path, f"expected a mapping, got {_type_name(value)}")
            return {}
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or key not in allowed:
                self.error(
                    path,
                    f"unknown key {_describe_key(key)}; allowed keys: {', '.join(sorted(allowed))}",
                )
                continue
            out[key] = item
        return out

    def boolean(self, data: Mapping[str, Any], key: str, path: str, default: bool) -> bool:
        if key not in data:
            return default
        value = data[key]
        if not isinstance(value, bool):
            self.error(_join(path, key), f"expected boolean, got {_type_name(value)}")
            return default
        return value

    def integer(
        self, data: Mapping[str, Any], key: str, path: str, default: int, lo: int, hi: int
    ) -> int:
        if key not in data:
            return default
        value = data[key]
        if isinstance(value, bool) or not isinstance(value, int):
            self.error(_join(path, key), f"expected integer, got {_type_name(value)}")
            return default
        if not lo <= value <= hi:
            self.error(_join(path, key), f"must be between {lo} and {hi}")
            return default
        return value

    def string(self, data: Mapping[str, Any], key: str, path: str, default: str) -> str:
        if key not in data:
            return default
        value = data[key]
        if not isinstance(value, str) or not value.strip():
            self.error(_join(path, key), f"expected non-empty string, got {_type_name(value)}")
            return default
        return value.strip()

    def enum(self, data: Mapping[str, Any], key: str, path: str, default: E) -> E:
        if key not in data:
            return default
        enum_type = type(default)
        value = data[key]
        if isinstance(value, str):
            for member in enum_type:
                if value.strip().lower() == member.value.lower():
                    return member
        allowed = ", ".join(m.value for m in enum_type)
        self.error(_join(path, key), f"must be one of: {allowed}")
        return default

    # -- whole-document scan --------------------------------------------------

    def scan_for_credentials(self, value: object, path: str = "") -> None:
        if isinstance(value, str):
            if _CREDENTIAL_PATTERN.search(value):
                self.error(
                    path,
                    "value looks like a credential; credentials must never be stored in the "
                    "EgressVeil config file (the value has not been printed)",
                )
        elif isinstance(value, Mapping):
            for k, v in value.items():
                self.scan_for_credentials(v, _join(path, k if isinstance(k, str) else "?"))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                self.scan_for_credentials(v, f"{path}[{i}]")


_ROOT_KEYS = frozenset(
    {"version", "gateway", "providers", "policy", "detectors", "audit", "telemetry"},
)
_GATEWAY_KEYS = frozenset(
    {
        "listen_host",
        "listen_port",
        "mode",
        "allow_non_loopback",
        "max_request_body_bytes",
        "max_stream_buffer_bytes",
    },
)
_PROVIDER_KEYS = frozenset({"enabled", "upstream_url", "allow_custom_upstream"})
_POLICY_KEYS = frozenset({"default_action", "rules"})
_RULE_KEYS = frozenset({"detector", "action"})
_DETECTOR_KEYS = frozenset({"enabled", "internal_domains"})
_AUDIT_KEYS = frozenset({"enabled", "path", "include_raw_values"})
_TELEMETRY_KEYS = frozenset({"enabled"})


def is_loopback_host(host: str) -> bool:
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _parse_gateway(v: _Validator, raw: object) -> GatewayConfig:
    path = "gateway"
    data = v.mapping(raw, path, _GATEWAY_KEYS)
    d = GatewayConfig()
    host = v.string(data, "listen_host", path, d.listen_host)
    allow_non_loopback = v.boolean(data, "allow_non_loopback", path, d.allow_non_loopback)
    if not is_loopback_host(host):
        if allow_non_loopback:
            v.warn(
                f"{path}.listen_host",
                "gateway will listen on a non-loopback interface; other hosts on the "
                "network may be able to send traffic through it",
            )
        else:
            v.error(
                f"{path}.listen_host",
                "must be a loopback address (127.0.0.1, ::1 or localhost); set "
                "gateway.allow_non_loopback: true to override",
            )
    mode = v.enum(data, "mode", path, d.mode)
    if mode is GatewayMode.PERMISSIVE:
        v.warn(
            f"{path}.mode",
            "permissive mode forwards uninspectable requests instead of blocking them",
        )
    return GatewayConfig(
        listen_host=host,
        listen_port=v.integer(data, "listen_port", path, d.listen_port, 1, 65535),
        mode=mode,
        allow_non_loopback=allow_non_loopback,
        max_request_body_bytes=v.integer(
            data, "max_request_body_bytes", path, d.max_request_body_bytes, 1 * KIB, 256 * MIB
        ),
        max_stream_buffer_bytes=v.integer(
            data, "max_stream_buffer_bytes", path, d.max_stream_buffer_bytes, 1 * KIB, 64 * MIB
        ),
    )


def _validate_upstream(v: _Validator, path: str, name: str, url: str, allow_custom: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        v.error(path, "upstream must use https://")
        return
    if parts.username is not None or parts.password is not None:
        v.error(path, "credentials must not be embedded in the upstream URL")
        return
    if parts.query or parts.fragment:
        v.error(path, "upstream URL must not contain a query string or fragment")
        return
    host = (parts.hostname or "").lower()
    if not host:
        v.error(path, "upstream URL has no host")
        return
    if host not in KNOWN_PROVIDERS[name].allowed_hosts:
        if allow_custom:
            v.warn(path, f"upstream host is not an official {name} endpoint")
        else:
            v.error(
                path,
                f"upstream host is not on the {name} allowlist; set "
                "allow_custom_upstream: true for this provider to override",
            )


def _parse_providers(v: _Validator, raw: object) -> dict[str, ProviderConfig]:
    providers = _default_providers()
    if raw is None:
        return providers
    data = v.mapping(raw, "providers", frozenset(KNOWN_PROVIDERS))
    for name, praw in data.items():
        path = f"providers.{name}"
        pdata = v.mapping(praw, path, _PROVIDER_KEYS)
        base = providers[name]
        allow_custom = v.boolean(pdata, "allow_custom_upstream", path, False)
        url = v.string(pdata, "upstream_url", path, base.upstream_url)
        _validate_upstream(v, f"{path}.upstream_url", name, url, allow_custom)
        providers[name] = ProviderConfig(
            name=name,
            enabled=v.boolean(pdata, "enabled", path, base.enabled),
            upstream_url=url.rstrip("/"),
            allow_custom_upstream=allow_custom,
        )
    if not any(p.enabled for p in providers.values()):
        v.warn("providers", "no provider is enabled; the gateway would forward nothing")
    return providers


def _parse_policy(v: _Validator, raw: object) -> PolicyConfig:
    path = "policy"
    data = v.mapping(raw, path, _POLICY_KEYS)
    d = PolicyConfig()
    default_action = v.enum(data, "default_action", path, d.default_action)
    if "rules" not in data:
        return PolicyConfig(default_action=default_action, rules=d.rules)
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        v.error(f"{path}.rules", f"expected a list, got {_type_name(raw_rules)}")
        return PolicyConfig(default_action=default_action, rules=d.rules)
    rules: list[PolicyRule] = []
    seen: set[str] = set()
    for i, rraw in enumerate(raw_rules):
        rpath = f"{path}.rules[{i}]"
        rdata = v.mapping(rraw, rpath, _RULE_KEYS)
        if "detector" not in rdata or "action" not in rdata:
            v.error(rpath, "each rule requires 'detector' and 'action'")
            continue
        detector = rdata["detector"]
        if not isinstance(detector, str) or detector not in DETECTOR_CATEGORIES:
            v.error(
                f"{rpath}.detector",
                f"must be one of: {', '.join(sorted(DETECTOR_CATEGORIES))}",
            )
            continue
        if detector in seen:
            v.error(f"{rpath}.detector", f"duplicate rule for detector {detector!r}")
            continue
        seen.add(detector)
        action = v.enum(rdata, "action", rpath, PolicyAction.BLOCK)
        if detector in {"secrets", "tokens"} and action in {
            PolicyAction.ALLOW,
            PolicyAction.LOG_ONLY,
        }:
            v.warn(f"{rpath}.action", f"{action.value} lets {detector} reach the upstream API")
        rules.append(PolicyRule(detector, action))
    return PolicyConfig(default_action=default_action, rules=tuple(rules))


def _parse_detectors(v: _Validator, raw: object) -> dict[str, DetectorConfig]:
    detectors = _default_detectors()
    if raw is None:
        return detectors
    data = v.mapping(raw, "detectors", DETECTOR_CATEGORIES)
    for name, draw in data.items():
        path = f"detectors.{name}"
        ddata = v.mapping(draw, path, _DETECTOR_KEYS)
        domains: list[str] = []
        if "internal_domains" in ddata:
            if name != "internal_hostnames":
                v.error(f"{path}.internal_domains", "only valid for detectors.internal_hostnames")
            elif not isinstance(ddata["internal_domains"], list):
                v.error(f"{path}.internal_domains", "expected a list of domain names")
            else:
                for i, dom in enumerate(ddata["internal_domains"]):
                    if not isinstance(dom, str) or not _DOMAIN.match(dom.strip().lstrip(".")):
                        v.error(f"{path}.internal_domains[{i}]", "not a valid domain name")
                    else:
                        domains.append(dom.strip().lstrip(".").lower())
        detectors[name] = DetectorConfig(
            name=name,
            enabled=v.boolean(ddata, "enabled", path, True),
            internal_domains=tuple(domains),
        )
    for name in ("secrets", "tokens"):
        if not detectors[name].enabled:
            v.warn(f"detectors.{name}", "detector is disabled")
    return detectors


def _parse_audit(v: _Validator, raw: object) -> AuditConfig:
    path = "audit"
    data = v.mapping(raw, path, _AUDIT_KEYS)
    d = AuditConfig()
    include_raw = v.boolean(data, "include_raw_values", path, False)
    if include_raw:
        v.error(
            f"{path}.include_raw_values",
            "logging raw sensitive values is not supported; must be false",
        )
    return AuditConfig(
        enabled=v.boolean(data, "enabled", path, d.enabled),
        path=v.string(data, "path", path, d.path),
        include_raw_values=False,
    )


def _parse_telemetry(v: _Validator, raw: object) -> bool:
    data = v.mapping(raw, "telemetry", _TELEMETRY_KEYS)
    enabled = v.boolean(data, "enabled", "telemetry", False)
    if enabled:
        v.error("telemetry.enabled", "EgressVeil has no telemetry; must be false")
    return False


def parse_config(raw: object) -> tuple[EgressVeilConfig | None, list[ValidationIssue]]:
    """Validate an already-parsed YAML document.

    Returns ``(config, issues)``. ``config`` is ``None`` when any issue is an
    error.
    """
    v = _Validator()
    v.scan_for_credentials(raw)
    data = v.mapping(raw, "", _ROOT_KEYS)

    if "version" in data:
        version = data["version"]
        if version != SCHEMA_VERSION or isinstance(version, bool):
            v.error("version", f"unsupported config schema version; expected {SCHEMA_VERSION}")

    config = EgressVeilConfig(
        version=SCHEMA_VERSION,
        gateway=_parse_gateway(v, data.get("gateway")),
        providers=_parse_providers(v, data.get("providers")),
        policy=_parse_policy(v, data.get("policy")),
        detectors=_parse_detectors(v, data.get("detectors")),
        audit=_parse_audit(v, data.get("audit")),
        telemetry_enabled=_parse_telemetry(v, data.get("telemetry")),
    )
    return (config if v.ok else None), v.issues


# --------------------------------------------------------------------------- discovery & IO


def user_config_dir() -> Path:
    """Platform-appropriate per-user configuration directory."""
    # Plain ``str`` so mypy type-checks every branch regardless of the host OS.
    plat: str = sys.platform
    if plat == "win32":
        base = os.environ.get("APPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Roaming") / "egressveil"
    if plat == "darwin":
        return Path.home() / "Library" / "Application Support" / "egressveil"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else Path.home() / ".config") / "egressveil"


@dataclass(frozen=True, slots=True)
class ConfigSource:
    path: Path | None
    origin: str  # "--config", "$EGRESSVEIL_CONFIG", "working directory", "user config", "defaults"


def discover_config(explicit: Path | None = None, cwd: Path | None = None) -> ConfigSource:
    """Find the configuration file to use, in priority order.

    1. ``--config PATH`` (must exist)
    2. ``$EGRESSVEIL_CONFIG`` (must exist)
    3. ``./egressveil.yaml``
    4. ``<user config dir>/egressveil.yaml``
    5. built-in defaults
    """
    if explicit is not None:
        return ConfigSource(explicit, "--config")
    env = os.environ.get(CONFIG_ENV_VAR)
    if env:
        return ConfigSource(Path(env), f"${CONFIG_ENV_VAR}")
    local = (cwd or Path.cwd()) / CONFIG_FILENAME
    if local.is_file():
        return ConfigSource(local, "working directory")
    user = user_config_dir() / CONFIG_FILENAME
    if user.is_file():
        return ConfigSource(user, "user config")
    return ConfigSource(None, "defaults")


@dataclass(frozen=True, slots=True)
class LoadResult:
    source: ConfigSource
    config: EgressVeilConfig | None
    issues: list[ValidationIssue]

    @property
    def ok(self) -> bool:
        return self.config is not None

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level is IssueLevel.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.level is IssueLevel.WARNING]


def _fail(source: ConfigSource, message: str) -> LoadResult:
    return LoadResult(source, None, [ValidationIssue(IssueLevel.ERROR, "", message)])


def load_config(explicit: Path | None = None, cwd: Path | None = None) -> LoadResult:
    """Discover, read, parse and validate configuration."""
    source = discover_config(explicit, cwd)
    if source.path is None:
        config, issues = parse_config({})
        return LoadResult(source, config, issues)

    path = source.path
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return _fail(source, f"config file not found (from {source.origin})")
    except OSError as exc:
        return _fail(source, f"cannot access config file: {exc.strerror or type(exc).__name__}")
    if not path.is_file():
        return _fail(source, "config path is not a regular file")
    if size > MAX_CONFIG_FILE_BYTES:
        return _fail(source, f"config file exceeds {MAX_CONFIG_FILE_BYTES} bytes")

    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return _fail(source, "config file is not valid UTF-8")
    except OSError as exc:
        return _fail(source, f"cannot read config file: {exc.strerror or type(exc).__name__}")

    try:
        raw = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        # Report position only: the problem/context snippets can contain file content.
        mark = exc.problem_mark
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        return _fail(source, f"invalid YAML{where}")
    except yaml.YAMLError:
        return _fail(source, "invalid YAML")

    config, issues = parse_config({} if raw is None else raw)
    return LoadResult(source, config, issues)
