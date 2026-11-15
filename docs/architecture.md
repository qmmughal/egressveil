# Architecture

> Status: Phase 0. Only configuration, the CLI and the doctor exist. This
> document describes the target design for the components that later phases
> will build.

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

| Module | Responsibility | Phase |
| --- | --- | --- |
| `egressveil.cli` | Typer CLI: `version`, `config validate`, `doctor` (later `serve`, `run`) | 0 |
| `egressveil.config` | Config discovery, strict schema validation, secure defaults | 0 |
| `egressveil.policy` | `PolicyAction`, `GatewayMode`; rule evaluation later | 0 / 1 |
| `egressveil.providers` | Provider registry and allowlists; request/response parsers later | 0 / 1 |
| `egressveil.detectors` | `Detector` protocol and `Finding`; concrete detectors later | 0 / 1 |
| `egressveil.proxy` | Async HTTP gateway, streaming, size limits | 1 |
| `egressveil.redactor` | Placeholder substitution | 1 |
| `egressveil.audit` | Append-only JSONL audit events | 1 |

## Request lifecycle (target)

1. **Accept.** The gateway accepts a connection on the loopback listener and
   reads the request body, up to `gateway.max_request_body_bytes`. A larger
   body gets `413` and is not forwarded.
2. **Route.** The request path and headers select a provider parser. If no
   parser matches, the result depends on the mode: strict mode returns an
   error, and permissive mode forwards the request with an audit event.
3. **Parse.** The parser extracts every model-bound text field (system
   prompt, message content, tool results, tool definitions) together with a
   JSON path for each one. If the body fails to parse, the request is treated
   as uninspectable (see step 2).
4. **Detect.** Every enabled detector scans every extracted field and
   produces `Finding`s. A `Finding` records offsets and a rule ID, never the
   matched text.
5. **Decide.** The policy engine maps each finding to an action. The most
   restrictive action wins, in the order `BLOCK` > `REDACT` > `LOG_ONLY` >
   `ALLOW`.
6. **Transform.** The redactor rewrites the affected fields, and the parser
   re-serializes the body.
7. **Audit.** One audit event per request records the provider, decision,
   counts per detector and rule, and keyed hashes for correlation.
8. **Forward.** The request goes over HTTPS to the allowlisted upstream. The
   agent's own `Authorization` / `x-api-key` header is passed through
   unchanged and never logged.
9. **Respond.** The response streams back to the agent. Streaming responses
   pass through a bounded buffer of `gateway.max_stream_buffer_bytes`.
   Response inspection is a later-phase feature.

## Extension points

- **Providers** implement a parser that extracts fields and re-serializes a
  request. Adding a provider means adding a `ProviderSpec` and a parser.
- **Detectors** implement the `Detector` protocol (`category`, and
  `scan(text) -> list[Finding]`).
- **Policies** are data (YAML), not code.

## Dependencies

The runtime dependencies are kept small and well known: Typer for the CLI
and PyYAML (always `safe_load`) for configuration. Phase 1 will add an async
HTTP stack, chosen for streaming support and a good security track record.
That choice will be documented here.
