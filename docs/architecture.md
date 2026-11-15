# Architecture

> Status: Phase 1. The gateway, the Anthropic parser, the secret and token
> detectors, the policy engine, the redactor and the audit log are
> implemented. PII and hostname detectors, and the OpenAI parser, are planned.

## Overview

```text
AI Coding Agent
       |
       v
EgressVeil Local Gateway        (listens on 127.0.0.1 by default)
       |
       +-- Provider Parser      (understands a provider's request schema)
       +-- Sensitive Data Detectors
       +-- Policy Engine        (ALLOW | REDACT | BLOCK | LOG_ONLY)
       +-- Redaction Engine
       +-- Audit Logger         (no raw values)
       |
       v
Supported LLM API               (https, allowlisted hosts only)
```

EgressVeil is an **application-layer reverse proxy** for specific LLM APIs.
The agent is configured to use `http://127.0.0.1:<port>` as its API base URL.
EgressVeil parses each request, inspects the text the request will send to the
model, applies policy, and forwards the (possibly modified) request over TLS
to the real provider.

This approach does **not** need TLS interception or a trusted root CA. It
also means EgressVeil sees only the traffic that the agent sends to the base
URL.

## Package layout

| Module | Responsibility |
| --- | --- |
| `egressveil.cli` | Typer CLI: `version`, `config validate`, `doctor`, `serve`, `scan` |
| `egressveil.config` | Config discovery, strict schema validation, secure defaults |
| `egressveil.proxy.server` | aiohttp gateway: host and origin checks, size limits, forwarding, streaming, audit |
| `egressveil.inspection` | A pure, synchronous pipeline: route, parse, detect, decide, redact |
| `egressveil.providers.base` | Hardened JSON parsing, the shared walker over every string field, and `ProviderAdapter` |
| `egressveil.providers.anthropic`, `.openai` | One adapter per API: inspected routes, opaque, signed and encrypted fields, error shape |
| `egressveil.detectors.pii`, `.hostnames` | PII rules (checksum-validated) and the internal-hostname detector |
| `egressveil.launcher` | `egressveil run`: starts the gateway on demand, sets the agent's environment, stops the gateway afterwards |
| `egressveil.doctor` | Environment checks, the canary self-test and the OpenClaw config check |
| `egressveil.responses` | Optional, audit-only response scanning: SSE delta reassembly and windowed scanning |
| `egressveil.detectors` | The `Detector` protocol, `Finding`, span merging, and the `patterns` secret and token rules |
| `egressveil.policy.engine` | Maps each finding to an action. The most restrictive action wins |
| `egressveil.redactor` | Keyed, stable placeholders |
| `egressveil.audit` | Key management and the append-only JSONL audit log |

## Request lifecycle

1. **Accept.** The loopback listener rejects a foreign `Host` (DNS
   rebinding) or a browser `Origin`. The `/_egressveil/health` endpoint is
   answered locally and never forwarded.
2. **Bound.** A declared `Content-Length` above `max_request_body_bytes`
   gets `413` before the body is read, and so does a chunked body that grows
   past the limit while it is read.
3. **Route.** Paths under `/openai/` go to the OpenAI adapter, with the
   prefix removed. Everything else goes to the Anthropic adapter. Each
   adapter lists its inspected JSON routes, for example `POST /v1/messages`
   or `POST /v1/chat/completions`. A bodyless `GET`/`HEAD` has only its URL
   inspected. Anything else is unsupported, and so is a provider that isn't
   enabled.
4. **Parse.** The body must be UTF-8 `application/json` and uncompressed.
   Duplicate keys, `NaN` and nesting deeper than 64 levels are rejected. The
   walker collects every string together with its JSON location. It marks
   base64 images and documents as *opaque*, and strings inside `thinking`
   blocks as *signed*.
5. **Detect.** Every enabled, implemented detector scans every field, plus
   the decoded query string. This runs in a worker thread so the event loop
   keeps streaming other responses.
6. **Decide.** The policy engine maps each finding to an action, and the
   most restrictive action wins. A `REDACT` in the URL escalates to `BLOCK`.
   Findings in provider-signed content (`thinking`) are recorded as
   `LOG_ONLY`. In strict mode, an uninspectable request becomes `BLOCK`. In
   permissive mode it is forwarded unchanged and flagged.
7. **Transform.** For `REDACT`, the affected strings are rewritten in place
   and the body is re-serialized as ASCII JSON. Otherwise the original bytes
   are forwarded.
8. **Forward.** The request goes to the allowlisted https upstream with
   verified TLS. Hop-by-hop headers, `Host` and `Origin` are dropped. The
   agent's `x-api-key` / `Authorization` header passes through untouched.
   Redirects are not followed. Environment proxies are ignored unless
   `gateway.upstream_proxy` says otherwise.
9. **Respond.** The response status and headers are relayed. The body is
   streamed in chunks of at most `max_stream_buffer_bytes` and is not
   decompressed. If the upstream fails mid-stream, the client connection is
   aborted.
10. **Audit.** One event per request records the outcome, the reason, and
    for each finding the rule, location and keyed digest. No content is
    recorded.

## Extension points

- **Providers** implement route classification and field extraction. The
  next one is the OpenAI-compatible parser (Phase 2).
- **Detectors** implement the `Detector` protocol (`category`, and
  `scan(text) -> list[Finding]`), and are registered in `build_detectors`
  and `IMPLEMENTED_CATEGORIES`.
- **Policies** are data (YAML), not code.

## Dependencies

The runtime dependencies are kept small and well known:

- **Typer**: the CLI.
- **PyYAML**: configuration, always loaded with `safe_load`.
- **aiohttp**: the HTTP server and the streaming HTTP client, in one mature
  package. It was chosen over the standard library's `http.server`, which
  Python's own documentation says is not intended for production use, and
  over a Starlette + Uvicorn + httpx stack, which would add three or more
  dependencies for the same capability. `pip-audit` checks it in CI every
  week.
