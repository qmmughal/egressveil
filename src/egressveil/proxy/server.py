"""The EgressVeil gateway: an inspecting reverse proxy for the Anthropic API.

Request flow: host/origin checks -> bounded body read -> inspection (in a worker
thread) -> block locally, or forward to the allowlisted upstream over verified
TLS -> stream the response back through a bounded buffer -> audit.

Never logged or audited: request bodies, header values (including the agent's
API key, which is passed upstream untouched), query strings, matched values.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import ssl
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import aiohttp
from aiohttp import web
from yarl import URL

from egressveil import __version__
from egressveil.audit import KEY_FILENAME, AuditLogger, load_or_create_key
from egressveil.config import EgressVeilConfig
from egressveil.detectors import IMPLEMENTED_CATEGORIES, build_detectors
from egressveil.inspection import Inspector, Outcome, Verdict
from egressveil.policy.engine import PolicyEngine
from egressveil.redactor import Redactor

if TYPE_CHECKING:
    from egressveil.config import ProviderConfig

__all__ = ["HEALTH_PATH", "GatewayComponents", "build_components", "create_app"]

log = logging.getLogger("egressveil")

HEALTH_PATH: Final = "/_egressveil/health"
INTERNAL_PREFIX: Final = "/_egressveil/"
REQUEST_ID_HEADER: Final = "x-egressveil-request-id"
DECISION_HEADER: Final = "x-egressveil-decision"

UPSTREAM_CONNECT_TIMEOUT: Final = 30.0
UPSTREAM_READ_TIMEOUT: Final = 600.0  # long generations stream slowly

# RFC 9110 section 7.6.1 hop-by-hop headers, plus headers we recompute.
_HOP_BY_HOP: Final = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_DROP_REQUEST: Final = _HOP_BY_HOP | {"host", "content-length", "origin"}
_DROP_RESPONSE: Final = _HOP_BY_HOP | {"content-length"}

_APP_KEY_STATE: Final = web.AppKey("egressveil_state", object)


@dataclass(slots=True)
class GatewayComponents:
    config: EgressVeilConfig
    provider: ProviderConfig
    inspector: Inspector
    audit: AuditLogger


def build_components(config: EgressVeilConfig) -> GatewayComponents:
    """Wire up key, audit log, detectors, policy and redactor from config."""
    provider = config.providers["anthropic"]
    if not provider.enabled:
        raise ValueError("the anthropic provider is disabled; nothing to serve")
    if config.audit.enabled:
        audit_path = config.audit.resolved_path
        key = load_or_create_key(audit_path.parent / KEY_FILENAME)
        audit = AuditLogger(audit_path, key)
    else:
        key = secrets.token_bytes(32)
        audit = AuditLogger(None, key)
    enabled = [n for n, d in config.detectors.items() if d.enabled and n in IMPLEMENTED_CATEGORIES]
    inspector = Inspector(
        detectors=build_detectors(enabled),
        engine=PolicyEngine(config.policy),
        redactor=Redactor(key),
        audit=audit,
        mode=config.gateway.mode,
        allow_opaque_content=config.gateway.allow_opaque_content,
    )
    return GatewayComponents(config, provider, inspector, audit)


def _error_body(error_type: str, message: str) -> dict[str, Any]:
    """Anthropic-shaped error so agents surface it to the user."""
    return {"type": "error", "error": {"type": error_type, "message": message}}


def _allowed_hosts(config: EgressVeilConfig) -> frozenset[str]:
    port = config.gateway.listen_port
    names = {"127.0.0.1", "localhost", "[::1]", config.gateway.listen_host.lower()}
    if ":" in config.gateway.listen_host:
        names.add(f"[{config.gateway.listen_host.lower()}]")
    return frozenset(names | {f"{n}:{port}" for n in names if not n.startswith(":")})


class _Gateway:
    def __init__(self, components: GatewayComponents, *, allow_insecure_upstream: bool) -> None:
        self.c = components
        upstream = URL(components.provider.upstream_url)
        if upstream.scheme != "https" and not allow_insecure_upstream:
            raise ValueError("upstream must use https")
        self.upstream = upstream
        self.allowed_hosts = _allowed_hosts(components.config)
        self.max_body = components.config.gateway.max_request_body_bytes
        self.chunk = components.config.gateway.max_stream_buffer_bytes
        self.session: aiohttp.ClientSession | None = None

    async def start(self, _app: web.Application) -> None:
        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context())
        self.session = aiohttp.ClientSession(
            connector=connector,
            auto_decompress=False,
            trust_env=False,  # never route via env proxies implicitly
            timeout=aiohttp.ClientTimeout(
                total=None, sock_connect=UPSTREAM_CONNECT_TIMEOUT, sock_read=UPSTREAM_READ_TIMEOUT
            ),
            skip_auto_headers=("User-Agent", "Accept-Encoding"),
        )

    async def stop(self, _app: web.Application) -> None:
        if self.session is not None:
            await self.session.close()

    # ------------------------------------------------------------------ helpers

    def _audit(self, rid: str, request: web.Request, started: float, **fields: Any) -> None:
        self.c.audit.write(
            {
                "request_id": rid,
                "provider": self.c.provider.name,
                "method": request.method,
                "path": request.path,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                **fields,
            }
        )

    def _reply_error(
        self, rid: str, status: int, error_type: str, message: str, decision: str
    ) -> web.Response:
        return web.json_response(
            _error_body(error_type, f"EgressVeil: {message} (request {rid})"),
            status=status,
            headers={REQUEST_ID_HEADER: rid, DECISION_HEADER: decision},
        )

    # ------------------------------------------------------------------ handler

    async def handle(self, request: web.Request) -> web.StreamResponse:
        rid = "ev_" + secrets.token_hex(8)
        started = time.monotonic()

        host = (request.headers.get("Host") or "").lower()
        if host not in self.allowed_hosts:
            self._audit(rid, request, started, outcome="block", reason="bad_host")
            return self._reply_error(
                rid,
                403,
                "permission_error",
                "request Host header is not the gateway's address",
                "block",
            )
        if request.headers.get("Origin"):
            self._audit(rid, request, started, outcome="block", reason="browser_origin")
            return self._reply_error(
                rid,
                403,
                "permission_error",
                "browser-originated requests are not accepted",
                "block",
            )

        if request.path.startswith(INTERNAL_PREFIX):
            if request.path == HEALTH_PATH and request.method in {"GET", "HEAD"}:
                return web.json_response(
                    {
                        "status": "ok",
                        "service": "egressveil",
                        "version": __version__,
                        "mode": self.c.config.gateway.mode.value,
                    },
                    headers={REQUEST_ID_HEADER: rid},
                )
            return self._reply_error(rid, 404, "not_found_error", "unknown internal path", "block")

        declared = request.content_length
        if declared is not None and declared > self.max_body:
            self._audit(rid, request, started, outcome="block", reason="body_too_large")
            return self._reply_error(
                rid,
                413,
                "request_too_large",
                f"request body exceeds {self.max_body} bytes",
                "block",
            )
        try:
            body = await request.read()
        except web.HTTPRequestEntityTooLarge:
            self._audit(rid, request, started, outcome="block", reason="body_too_large")
            return self._reply_error(
                rid,
                413,
                "request_too_large",
                f"request body exceeds {self.max_body} bytes",
                "block",
            )

        loop = asyncio.get_running_loop()
        verdict: Verdict = await loop.run_in_executor(
            None,
            lambda: self.c.inspector.inspect_request(
                method=request.method,
                path=request.path,
                query=request.query_string,
                content_type=request.headers.get("Content-Type"),
                content_encoding=request.headers.get("Content-Encoding"),
                body=body,
            ),
        )
        audit_fields: dict[str, Any] = {
            "route": verdict.route.value,
            "inspected": verdict.inspected,
            "bytes_in": len(body),
            "findings": [f.as_audit() for f in verdict.findings],
        }
        if verdict.reason:
            audit_fields["reason"] = verdict.reason
        if verdict.opaque:
            audit_fields["opaque"] = [
                {"location": o.location, "kind": o.kind} for o in verdict.opaque
            ]

        if verdict.outcome is Outcome.BLOCK:
            self._audit(rid, request, started, outcome="block", **audit_fields)
            hint = (
                " Remove the value from the conversation (for example start a new session) "
                "or adjust the EgressVeil policy."
                if verdict.reason == "policy"
                else ""
            )
            return self._reply_error(
                rid,
                400,
                "invalid_request_error",
                f"request blocked before leaving this machine: {verdict.message}.{hint}",
                "block",
            )

        decision = "redact" if verdict.outcome is Outcome.REDACT else "forward"
        return await self._forward(request, rid, started, verdict.body, decision, audit_fields)

    async def _forward(
        self,
        request: web.Request,
        rid: str,
        started: float,
        body: bytes,
        decision: str,
        audit_fields: dict[str, Any],
    ) -> web.StreamResponse:
        assert self.session is not None  # noqa: S101 - set in on_startup
        headers = [(k, v) for k, v in request.headers.items() if k.lower() not in _DROP_REQUEST]
        target = URL(str(self.upstream).rstrip("/") + request.raw_path, encoded=True)
        try:
            upstream = await self.session.request(
                request.method,
                target,
                headers=headers,
                data=body if body else None,
                allow_redirects=False,
            )
        except (TimeoutError, aiohttp.ServerTimeoutError):
            self._audit(
                rid, request, started, outcome="error", reason="upstream_timeout", **audit_fields
            )
            return self._reply_error(rid, 504, "api_error", "upstream timed out", "error")
        except aiohttp.ClientError:
            self._audit(
                rid,
                request,
                started,
                outcome="error",
                reason="upstream_unreachable",
                **audit_fields,
            )
            return self._reply_error(rid, 502, "api_error", "upstream unreachable", "error")

        async with upstream:
            response = web.StreamResponse(status=upstream.status, reason=upstream.reason)
            for key, value in upstream.headers.items():
                if key.lower() not in _DROP_RESPONSE:
                    response.headers.add(key, value)
            if upstream.content_length is not None and request.method != "HEAD":
                response.content_length = upstream.content_length
            response.headers[REQUEST_ID_HEADER] = rid
            response.headers[DECISION_HEADER] = decision
            await response.prepare(request)
            complete = False
            try:
                async for chunk in upstream.content.iter_chunked(self.chunk):
                    await response.write(chunk)
                await response.write_eof()
                complete = True
            except (aiohttp.ClientError, TimeoutError):
                # Upstream failed mid-stream: abort the client connection rather
                # than ending cleanly, so the agent sees a truncated response.
                if request.transport is not None:
                    request.transport.close()
            except ConnectionResetError:
                pass  # client went away
            self._audit(
                rid,
                request,
                started,
                outcome=decision,
                upstream_status=upstream.status,
                stream_complete=complete,
                **audit_fields,
            )
            return response


def create_app(
    components: GatewayComponents, *, allow_insecure_upstream: bool = False
) -> web.Application:
    """Build the aiohttp application.

    ``allow_insecure_upstream`` exists only so the test-suite can use a plain
    HTTP mock upstream. It is not reachable from configuration or the CLI.
    """
    gateway = _Gateway(components, allow_insecure_upstream=allow_insecure_upstream)
    app = web.Application(client_max_size=gateway.max_body)
    app[_APP_KEY_STATE] = gateway
    app.on_startup.append(gateway.start)
    app.on_cleanup.append(gateway.stop)
    app.router.add_route("*", "/{tail:.*}", gateway.handle)
    return app
