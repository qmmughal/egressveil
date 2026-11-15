"""The EgressVeil gateway: an inspecting reverse proxy for LLM APIs.

Routing: ``/openai/...`` goes to the OpenAI-compatible upstream (prefix
removed); everything else goes to the Anthropic upstream.

Request flow: host/origin checks -> bounded body read -> inspection (worker
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
from typing import Any, Final

import aiohttp
from aiohttp import web
from yarl import URL

from egressveil import __version__
from egressveil.audit import KEY_FILENAME, AuditLogger, load_or_create_key
from egressveil.config import EgressVeilConfig, ProviderConfig, config_fingerprint
from egressveil.inspection import Inspector, Outcome, Verdict
from egressveil.providers import adapter_for_path
from egressveil.providers.base import ProviderAdapter
from egressveil.redactor import Redactor
from egressveil.responses import ResponseScanner

__all__ = ["HEALTH_PATH", "GatewayComponents", "build_components", "create_app"]

log = logging.getLogger("egressveil")

HEALTH_PATH: Final = "/_egressveil/health"
HEALTH_SCHEMA_VERSION: Final = 1
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
    providers: dict[str, ProviderConfig]
    """Enabled providers only."""
    inspector: Inspector
    audit: AuditLogger


def build_components(config: EgressVeilConfig) -> GatewayComponents:
    """Wire up key, audit log, detectors, policy and redactor from config."""
    providers = {name: p for name, p in config.providers.items() if p.enabled}
    if not providers:
        raise ValueError("no provider is enabled; nothing to serve")
    if config.audit.enabled:
        audit_path = config.audit.resolved_path
        key = load_or_create_key(audit_path.parent / KEY_FILENAME)
        audit = AuditLogger(audit_path, key)
    else:
        key = secrets.token_bytes(32)
        audit = AuditLogger(None, key)
    inspector = Inspector.from_config(config, redactor=Redactor(key), audit=audit)
    return GatewayComponents(config, providers, inspector, audit)


def _allowed_hosts(config: EgressVeilConfig) -> frozenset[str]:
    port = config.gateway.listen_port
    names = {"127.0.0.1", "localhost", "[::1]", config.gateway.listen_host.lower()}
    if ":" in config.gateway.listen_host:
        names.add(f"[{config.gateway.listen_host.lower()}]")
    return frozenset(names | {f"{n}:{port}" for n in names if not n.startswith(":")})


class _Gateway:
    def __init__(self, components: GatewayComponents, *, allow_insecure_upstream: bool) -> None:
        self.c = components
        self.upstreams: dict[str, URL] = {}
        for name, provider in components.providers.items():
            url = URL(provider.upstream_url)
            if url.scheme != "https" and not allow_insecure_upstream:
                raise ValueError(f"{name} upstream must use https")
            self.upstreams[name] = url
        gw = components.config.gateway
        self.allowed_hosts = _allowed_hosts(components.config)
        self.max_body = gw.max_request_body_bytes
        self.chunk = gw.max_stream_buffer_bytes
        self.proxy: str | None = (
            gw.upstream_proxy if gw.upstream_proxy not in {"none", "env"} else None
        )
        self.trust_env = gw.upstream_proxy == "env"
        self.inspect_responses = gw.inspect_responses
        self.fingerprint = config_fingerprint(components.config)
        self.session: aiohttp.ClientSession | None = None

    async def start(self, _app: web.Application) -> None:
        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context())
        self.session = aiohttp.ClientSession(
            connector=connector,
            auto_decompress=False,
            # Only honour HTTPS_PROXY/NO_PROXY when explicitly configured.
            trust_env=self.trust_env,
            timeout=aiohttp.ClientTimeout(
                total=None, sock_connect=UPSTREAM_CONNECT_TIMEOUT, sock_read=UPSTREAM_READ_TIMEOUT
            ),
            skip_auto_headers=("User-Agent", "Accept-Encoding"),
        )

    async def stop(self, _app: web.Application) -> None:
        if self.session is not None:
            await self.session.close()

    # ------------------------------------------------------------------ helpers

    def _audit(
        self, rid: str, request: web.Request, provider: str, started: float, **fields: Any
    ) -> None:
        self.c.audit.write(
            {
                "request_id": rid,
                "provider": provider,
                "method": request.method,
                "path": request.path,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                **fields,
            }
        )

    @staticmethod
    def _reply_error(
        adapter: ProviderAdapter,
        rid: str,
        status: int,
        error_type: str,
        message: str,
        decision: str,
    ) -> web.Response:
        return web.json_response(
            adapter.error_body(error_type, f"EgressVeil: {message} (request {rid})"),
            status=status,
            headers={REQUEST_ID_HEADER: rid, DECISION_HEADER: decision},
        )

    # ------------------------------------------------------------------ handler

    async def handle(self, request: web.Request) -> web.StreamResponse:
        rid = "ev_" + secrets.token_hex(8)
        started = time.monotonic()
        adapter, upstream_path = adapter_for_path(request.path)
        name = adapter.name

        def deny(status: int, error_type: str, message: str, reason: str) -> web.Response:
            self._audit(rid, request, name, started, outcome="block", reason=reason)
            return self._reply_error(adapter, rid, status, error_type, message, "block")

        host = (request.headers.get("Host") or "").lower()
        if host not in self.allowed_hosts:
            return deny(
                403,
                "permission_error",
                "request Host header is not the gateway's address",
                "bad_host",
            )
        if request.headers.get("Origin"):
            return deny(
                403,
                "permission_error",
                "browser-originated requests are not accepted",
                "browser_origin",
            )

        if request.path.startswith(INTERNAL_PREFIX):
            if request.path == HEALTH_PATH and request.method in {"GET", "HEAD"}:
                return web.json_response(
                    {
                        "schema_version": HEALTH_SCHEMA_VERSION,
                        "status": "ok",
                        "service": "egressveil",
                        "version": __version__,
                        "mode": self.c.config.gateway.mode.value,
                        "providers": sorted(self.upstreams),
                        "config": self.fingerprint,
                        "inspect_responses": self.inspect_responses,
                    },
                    headers={REQUEST_ID_HEADER: rid},
                )
            return self._reply_error(
                adapter, rid, 404, "not_found_error", "unknown internal path", "block"
            )

        if name not in self.upstreams:
            return deny(
                404,
                "not_found_error",
                f"the {name} provider is not enabled in the EgressVeil configuration",
                "provider_disabled",
            )

        declared = request.content_length
        if declared is not None and declared > self.max_body:
            return deny(
                413,
                "request_too_large",
                f"request body exceeds {self.max_body} bytes",
                "body_too_large",
            )
        try:
            body = await request.read()
        except web.HTTPRequestEntityTooLarge:
            return deny(
                413,
                "request_too_large",
                f"request body exceeds {self.max_body} bytes",
                "body_too_large",
            )

        loop = asyncio.get_running_loop()
        verdict: Verdict = await loop.run_in_executor(
            None,
            lambda: self.c.inspector.inspect_request(
                adapter=adapter,
                method=request.method,
                path=upstream_path,
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
            self._audit(rid, request, name, started, outcome="block", **audit_fields)
            hint = (
                " Remove the value from the conversation (for example start a new session) "
                "or adjust the EgressVeil policy."
                if verdict.reason == "policy"
                else ""
            )
            return self._reply_error(
                adapter,
                rid,
                400,
                "invalid_request_error",
                f"request blocked before leaving this machine: {verdict.message}.{hint}",
                "block",
            )

        decision = "redact" if verdict.outcome is Outcome.REDACT else "forward"
        target = self._upstream_target(request, adapter, upstream_path)
        if target is None:
            self._audit(
                rid,
                request,
                name,
                started,
                outcome="block",
                reason="ambiguous_path",
                **audit_fields,
            )
            return self._reply_error(
                adapter,
                rid,
                400,
                "invalid_request_error",
                "request path is ambiguous and was not forwarded",
                "block",
            )
        return await self._forward(
            request, adapter, rid, started, target, verdict.body, decision, audit_fields
        )

    def _upstream_target(
        self, request: web.Request, adapter: ProviderAdapter, inspected_path: str
    ) -> URL | None:
        """Build the upstream URL from exactly the path that was inspected.

        Uses the normalised origin-form path (``rel_url``), never the raw
        request target, so an absolute-form target such as
        ``POST http://other.host/v1/messages`` can't change what is forwarded.
        Returns ``None`` (refuse) if the encoded path doesn't decode to the
        inspected path (e.g. ``%2F`` tricks) or the final URL would leave the
        configured upstream origin.
        """
        base = self.upstreams[adapter.name]
        rel = request.rel_url
        raw_path = rel.raw_path
        if adapter.mount:
            if not raw_path.startswith(adapter.mount):
                return None
            raw_path = raw_path[len(adapter.mount) :] or "/"
        if not raw_path.startswith("/") or URL.build(path=raw_path, encoded=True).path != (
            inspected_path
        ):
            return None
        # Encoded "/", "." and "\\" in API paths are never sent by real clients and
        # could make the upstream route differently from what was inspected.
        lowered = raw_path.lower()
        if any(seq in lowered for seq in ("%2f", "%2e", "%5c")):
            return None
        text = str(base).rstrip("/") + raw_path
        if rel.raw_query_string:
            text += "?" + rel.raw_query_string
        target = URL(text, encoded=True)
        if (target.scheme, target.host, target.port) != (base.scheme, base.host, base.port):
            return None
        return target

    async def _forward(
        self,
        request: web.Request,
        adapter: ProviderAdapter,
        rid: str,
        started: float,
        target: URL,
        body: bytes,
        decision: str,
        audit_fields: dict[str, Any],
    ) -> web.StreamResponse:
        assert self.session is not None  # noqa: S101 - set in on_startup
        name = adapter.name
        headers = [(k, v) for k, v in request.headers.items() if k.lower() not in _DROP_REQUEST]
        if self.inspect_responses:
            # Uncompressed responses can be inspected without decoding on the side.
            headers = [(k, v) for k, v in headers if k.lower() != "accept-encoding"]
            headers.append(("Accept-Encoding", "identity"))
        try:
            # ``target`` keeps the configured upstream's scheme, host and port:
            # _upstream_target() builds it from the inspected path only and
            # refuses anything whose origin would differ (tests/test_http_edges.py).
            # Forwarding the client's path is the purpose of a reverse proxy.
            upstream = await self.session.request(
                request.method,
                target,
                headers=headers,
                data=body if body else None,
                allow_redirects=False,
                proxy=self.proxy,
            )
        except (TimeoutError, aiohttp.ServerTimeoutError):
            self._audit(
                rid,
                request,
                name,
                started,
                outcome="error",
                reason="upstream_timeout",
                **audit_fields,
            )
            return self._reply_error(adapter, rid, 504, "api_error", "upstream timed out", "error")
        except aiohttp.ClientError:
            self._audit(
                rid,
                request,
                name,
                started,
                outcome="error",
                reason="upstream_unreachable",
                **audit_fields,
            )
            return self._reply_error(
                adapter, rid, 502, "api_error", "upstream unreachable", "error"
            )

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
            scanner: ResponseScanner | None = None
            if self.inspect_responses:
                encoding = upstream.headers.get("Content-Encoding", "identity").lower()
                candidate = ResponseScanner(
                    self.c.inspector, upstream.headers.get("Content-Type"), self.max_body
                )
                if encoding == "identity" and candidate.active:
                    scanner = candidate
            complete = False
            try:
                async for chunk in upstream.content.iter_chunked(self.chunk):
                    if scanner is not None:
                        scanner.feed(chunk)
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
            if scanner is not None:
                audit_fields["response_findings"] = scanner.finish()
                if scanner.truncated:
                    audit_fields["response_inspection"] = "truncated"
            elif self.inspect_responses:
                audit_fields["response_inspection"] = "skipped"
            self._audit(
                rid,
                request,
                name,
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
