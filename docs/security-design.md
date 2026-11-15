# Security Design

This document lists EgressVeil's security controls. For each one it says
whether it is **enforced today** (Phase 0, in config validation) or
**planned** (the runtime behavior in later phases).

## 1. Local-only listening by default

- `gateway.listen_host` defaults to `127.0.0.1`.
- **Enforced today:** a non-loopback address is a validation error unless
  `gateway.allow_non_loopback: true` is also set, and even then validation
  emits a warning.
- **Planned:** the gateway refuses to start on an invalid configuration.

## 2. Provider endpoint allowlisting

- Each known provider has a fixed set of official hosts (see
  `egressveil.providers.KNOWN_PROVIDERS`).
- **Enforced today:** upstream URLs must be `https://`, must not embed
  credentials, query strings or fragments, and must point to an allowlisted
  host. A custom host needs `allow_custom_upstream: true` for that provider
  and produces a warning.
- **Planned:** the gateway connects only to the configured upstream and
  verifies TLS certificates with the system trust store. There is no option
  to disable verification.

## 3. Detection

The planned detector categories are `secrets`, `tokens`, `pii` and
`internal_hostnames`.

- Detectors return `Finding(detector, rule_id, start, end, confidence)`. A
  finding holds **no matched text**, so findings are always safe to log or
  display.
- Secret detection combines provider-specific patterns with entropy checks
  and context keywords.
- The internal-hostname detector matches the configured
  `internal_domains` suffixes.

## 4. Policy actions

| Action | Behavior |
| --- | --- |
| `ALLOW` | Forward unchanged, record nothing |
| `REDACT` | Replace each span with a placeholder such as `[EGRESSVEIL:secrets:3f9a]`, then forward |
| `BLOCK` | Send nothing upstream, and return a provider-shaped error to the agent |
| `LOG_ONLY` | Forward unchanged and write an audit event |

When findings conflict, the most restrictive action wins. By default,
secrets and tokens are blocked and PII and hostnames are redacted.
Configuring `ALLOW` or `LOG_ONLY` for secrets or tokens produces a warning.

## 5. Fail-closed behavior (strict mode)

`gateway.mode: strict` is the default. In strict mode the gateway returns an
error instead of forwarding when any of these is true:

- no provider parser matches the request,
- the body can't be parsed, or uses an unsupported encoding or compression,
- the body exceeds the size limit,
- a detector raises an error.

`permissive` mode forwards these requests with an audit event and is meant
only for evaluation. Validation warns when it is enabled.

## 6. Safe audit logging

- **Enforced today:** `audit.include_raw_values: true` is rejected.
- **Planned:** events are JSONL with timestamp, provider, decision, counts per
  detector and rule, and HMAC-SHA256 digests of matched values under a local
  random key. Digests let you correlate repeat occurrences without
  storing the value. Request bodies, headers and credentials are never logged.
- The audit file is created with user-only permissions where the OS supports
  that.

## 7. No telemetry

EgressVeil contains no telemetry, analytics or update pings. **Enforced
today:** `telemetry.enabled: true` is rejected. The only key exists to make
that explicit.

## 8. No automatic restoration into tool calls

Some redaction proxies "un-redact" model responses so the user sees original
values. EgressVeil does **not** automatically restore a secret into model
output that the agent may execute, such as a tool-use block or a shell
command. A model, or a prompt injection, could otherwise trick the gateway
into putting a real credential into a command that sends it somewhere. Any
future restoration feature will be opt-in, limited to display-only text, and
documented separately.

## 9. Bounded bodies and streaming buffers

- `gateway.max_request_body_bytes`: default 16 MiB, allowed range 1 KiB to 256 MiB.
- `gateway.max_stream_buffer_bytes`: default 1 MiB, allowed range 1 KiB to 64 MiB.
- **Enforced today:** values outside these ranges are rejected.
- **Planned:** an oversized request gets `413`, and a stream that exceeds its
  buffer is terminated.

## 10. Configuration hygiene

- **Enforced today:**
  - `yaml.safe_load` only, so YAML tags cannot construct objects
  - the config file is capped at 1 MiB
  - the schema rejects unknown keys
  - a config file containing credential-shaped strings is rejected
  - validation messages name the key path and the expected type, never the value
  - YAML syntax errors report only the line and column

## 11. Proxy bypass limitations

EgressVeil can protect only what passes through it. The
[threat model](threat-model.md) and [integrations](integrations.md) documents
list what bypasses it. Do not present EgressVeil as complete egress control.
