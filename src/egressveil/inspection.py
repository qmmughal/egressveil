"""Request inspection pipeline: parse -> detect -> decide -> redact.

This module is pure and synchronous. It knows nothing about HTTP sockets, which
keeps it easy to test and lets the gateway run it in a worker thread.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote_plus

from egressveil.policy import GatewayMode, PolicyAction
from egressveil.policy.engine import SEVERITY, PolicyEngine, most_restrictive
from egressveil.providers.anthropic import (
    OpaqueItem,
    RouteKind,
    TextField,
    UninspectableError,
    classify_route,
    parse_json_body,
    walk_body,
)

if TYPE_CHECKING:
    from egressveil.audit import AuditLogger
    from egressveil.detectors import Detector, Finding
    from egressveil.redactor import Redactor

__all__ = ["URL_LOCATION", "Inspector", "LocatedFinding", "Outcome", "Verdict"]

URL_LOCATION: Final = "$url"
_JSON_TYPES: Final = frozenset({"application/json"})


class Outcome(StrEnum):
    FORWARD = "forward"
    """Send the original bytes upstream unchanged."""
    REDACT = "redact"
    """Send the rewritten body upstream."""
    BLOCK = "block"
    """Send nothing upstream."""


@dataclass(frozen=True, slots=True)
class LocatedFinding:
    detector: str
    rule_id: str
    location: str
    action: PolicyAction
    digest: str
    escalated: bool = False

    def as_audit(self) -> dict[str, object]:
        out: dict[str, object] = {
            "detector": self.detector,
            "rule_id": self.rule_id,
            "location": self.location,
            "action": self.action.value,
            "digest": self.digest,
        }
        if self.escalated:
            out["escalated"] = True
        return out


@dataclass(slots=True)
class Verdict:
    outcome: Outcome
    body: bytes
    route: RouteKind
    findings: list[LocatedFinding] = field(default_factory=list)
    reason: str | None = None
    """Machine code for why a request was blocked or forwarded uninspected."""
    message: str | None = None
    """Human explanation. Contains locations and rule IDs only, never values."""
    opaque: list[OpaqueItem] = field(default_factory=list)
    inspected: bool = True


class Inspector:
    def __init__(
        self,
        *,
        detectors: Sequence[Detector],
        engine: PolicyEngine,
        redactor: Redactor,
        audit: AuditLogger,
        mode: GatewayMode,
        allow_opaque_content: bool,
    ) -> None:
        self._detectors = tuple(detectors)
        self._engine = engine
        self._redactor = redactor
        self._audit = audit
        self._strict = mode is GatewayMode.STRICT
        self._allow_opaque = allow_opaque_content

    # ------------------------------------------------------------------ text

    def scan_text(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.scan(text))
        return findings

    def action_for(self, finding: Finding) -> PolicyAction:
        return self._engine.action_for(finding)

    # ------------------------------------------------------------------ request

    def inspect_request(
        self,
        *,
        method: str,
        path: str,
        query: str,
        content_type: str | None,
        content_encoding: str | None,
        body: bytes,
    ) -> Verdict:
        route = classify_route(method, path, has_body=bool(body))
        try:
            return self._inspect(route, query, content_type, content_encoding, body)
        except UninspectableError as exc:
            return self._uninspectable(route, body, exc.reason, exc.message)
        except Exception:  # a detector bug must never fail open in strict mode
            return self._uninspectable(
                route, body, "detector_error", "internal error while inspecting the request"
            )

    def _uninspectable(self, route: RouteKind, body: bytes, reason: str, message: str) -> Verdict:
        if self._strict:
            return Verdict(
                Outcome.BLOCK, b"", route, reason=reason, message=message, inspected=False
            )
        return Verdict(
            Outcome.FORWARD, body, route, reason=reason, message=message, inspected=False
        )

    def _inspect(
        self,
        route: RouteKind,
        query: str,
        content_type: str | None,
        content_encoding: str | None,
        body: bytes,
    ) -> Verdict:
        if route is RouteKind.UNSUPPORTED:
            raise UninspectableError(
                "unsupported_route", "this API endpoint is not supported by EgressVeil"
            )

        located: list[LocatedFinding] = []
        if query:
            located.extend(self._scan_url(query))

        if route is RouteKind.BODYLESS:
            return self._decide(route, body, located, opaque=[])

        media_type = (content_type or "").split(";", 1)[0].strip().lower()
        if media_type not in _JSON_TYPES:
            raise UninspectableError(
                "unsupported_content_type", "request body must be application/json"
            )
        encoding = (content_encoding or "identity").strip().lower()
        if encoding != "identity":
            raise UninspectableError(
                "unsupported_content_encoding", "compressed request bodies are not supported"
            )

        document = parse_json_body(body)
        fields, opaque = walk_body(document)
        if opaque and not self._allow_opaque and self._strict:
            where = ", ".join(o.location for o in opaque[:3])
            raise UninspectableError(
                "opaque_content",
                f"request contains content EgressVeil cannot inspect (e.g. images or PDFs) at "
                f"{where}; set gateway.allow_opaque_content: true to forward such content",
            )

        per_field: list[tuple[TextField, list[Finding]]] = []
        for text_field in fields:
            raw_findings = [
                f
                for f in self.scan_text(text_field.text)
                if self.action_for(f) is not PolicyAction.ALLOW
            ]
            if not raw_findings:
                continue
            per_field.append((text_field, raw_findings))
            for f in raw_findings:
                action = self.action_for(f)
                escalated = text_field.signed and SEVERITY[action] >= SEVERITY[PolicyAction.REDACT]
                located.append(
                    LocatedFinding(
                        f.detector,
                        f.rule_id,
                        text_field.location,
                        PolicyAction.BLOCK if escalated else action,
                        self._audit.digest(text_field.text[f.start : f.end]),
                        escalated,
                    )
                )

        verdict = self._decide(route, body, located, opaque=opaque)
        if verdict.outcome is Outcome.REDACT:
            for text_field, raw_findings in per_field:
                to_redact = [f for f in raw_findings if self.action_for(f) is PolicyAction.REDACT]
                if to_redact:
                    text_field.replace(self._redactor.redact(text_field.text, to_redact))
            verdict.body = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode(
                "ascii"
            )
        return verdict

    def _scan_url(self, query: str) -> list[LocatedFinding]:
        decoded = unquote_plus(query)
        out: list[LocatedFinding] = []
        for f in self.scan_text(decoded):
            action = self.action_for(f)
            if action is PolicyAction.ALLOW:
                continue
            # URLs cannot be rewritten safely, so REDACT escalates to BLOCK.
            escalated = action is PolicyAction.REDACT
            out.append(
                LocatedFinding(
                    f.detector,
                    f.rule_id,
                    URL_LOCATION,
                    PolicyAction.BLOCK if escalated else action,
                    self._audit.digest(decoded[f.start : f.end]),
                    escalated,
                )
            )
        return out

    def _decide(
        self,
        route: RouteKind,
        body: bytes,
        located: list[LocatedFinding],
        *,
        opaque: list[OpaqueItem],
    ) -> Verdict:
        action = most_restrictive(f.action for f in located)
        reason = "opaque_content_forwarded" if opaque else None
        if action is PolicyAction.BLOCK:
            blocking = [f for f in located if f.action is PolicyAction.BLOCK]
            shown = "; ".join(f"{f.detector}/{f.rule_id} at {f.location}" for f in blocking[:5])
            more = f" (+{len(blocking) - 5} more)" if len(blocking) > 5 else ""
            return Verdict(
                Outcome.BLOCK,
                b"",
                route,
                located,
                reason="policy",
                message=f"sensitive data detected: {shown}{more}",
                opaque=opaque,
            )
        if action is PolicyAction.REDACT:
            return Verdict(Outcome.REDACT, body, route, located, reason=reason, opaque=opaque)
        return Verdict(Outcome.FORWARD, body, route, located, reason=reason, opaque=opaque)
