# Security Design

This document lists EgressVeil's security controls. For each one it says
whether it is **implemented** (as of Phase 1) or **planned**.

## 1. Local-only listening by default

- **Implemented:**
  - `gateway.listen_host` defaults to `127.0.0.1`.
  - A non-loopback address is a validation error unless
    `gateway.allow_non_loopback: true` is also set, and even then validation
    emits a warning.
  - `egressveil serve` refuses to start on an invalid configuration.
- **Implemented:** the **Host header** of every request must be one of the
  gateway's own addresses (`127.0.0.1:<port>`, `localhost:<port>`,
  `[::1]:<port>`). This defeats DNS-rebinding attacks, where a web page
  resolves its own domain to `127.0.0.1` in order to reach local services.
- **Implemented:** any request with an `Origin` header is rejected. Browsers
  set that header and agent CLIs don't, so web pages can't use the gateway
  through cross-site requests.

## 2. Provider endpoint allowlisting

- Each known provider has a fixed set of official hosts (see
  `egressveil.providers.KNOWN_PROVIDERS`).
- **Implemented:** upstream URLs must be `https://`, must not embed
  credentials, query strings or fragments, and must point to an allowlisted
  host. A custom host needs `allow_custom_upstream: true` for that provider
  and produces a warning.
- **Implemented:** the gateway connects only to the configured upstream and
  verifies TLS with the system trust store
  (`ssl.create_default_context()`). There is no option to disable
  verification.
- **Implemented:** upstream redirects are **not followed**. They go back to
  the agent as they are.
- **Implemented:** environment proxies (`HTTPS_PROXY`) are **not** used by
  default (`trust_env=False`), so traffic can't be sent somewhere unexpected
  without you noticing. For corporate networks, set
  `gateway.upstream_proxy: env` to honour `HTTPS_PROXY`/`NO_PROXY`, or give
  an explicit `http(s)://host:port`. Proxy credentials in the config file
  are rejected; put them in the environment and use `env`. TLS to the
  provider is still verified end to end through the proxy's tunnel.

## 3. What is inspected

- **Implemented:** each provider adapter (Anthropic, and OpenAI-compatible
  under `/openai`) walks **every string** in the JSON body: system prompts,
  messages, tool definitions, tool calls and arguments, tool results, and
  fields it doesn't know about. A new API field therefore can't carry text
  past the detectors. The only values it skips are identifier-like control
  values (`model`, `type`, `role`, `id`, ...) and provider-issued blobs
  (Anthropic `signature` and `redacted_thinking`, OpenAI
  `encrypted_content`).
- **Implemented:** base64 `data:` URIs, inline audio and inline files are
  treated as opaque, the same way as images (see section 6).
- **Implemented:** the query string is scanned. Because a URL can't be
  rewritten safely, a finding there that would be redacted is blocked instead.
- **Implemented:** JSON is decoded before scanning, so `\uXXXX` escapes
  can't hide a value.
- **Implemented:** hardening against parser differentials. Duplicate keys,
  `NaN`/`Infinity`, non-object roots and nesting deeper than 64 levels make a
  request uninspectable. This guarantees EgressVeil inspects the same
  document the upstream parses.
- **Not inspected:** headers. The agent's `x-api-key` / `Authorization`
  header is forwarded untouched.
- **Optional:** responses (`gateway.inspect_responses: true`). They are
  scanned and audited but never modified (see section 13).

## 4. Detection

- **Implemented:** `secrets` and `tokens` (see
  `egressveil/detectors/patterns.py`).
  - **Vendor rules** match known key prefixes: Anthropic, OpenAI, AWS,
    GitHub, GitLab, Slack, Stripe, Google, npm and Hugging Face. There are
    also rules for PEM private keys and passwords embedded in URLs.
  - **Generic rules** match `password = "..."`-style and `.env`-style
    assignments. To keep false positives on ordinary code low, they fire
    only on quoted or `.env` values with at least one digit and an entropy of
    at least 3.0 bits per character, and they ignore placeholders.
  - **Token rules** match JWTs, bearer tokens and Basic auth headers.
  - Every quantifier is bounded, to avoid regex denial of service. A test
    checks that a 1 MB input is scanned in well under the limit.
- Detectors return `Finding(detector, rule_id, start, end, confidence)`. A
  finding holds **no matched text**.
- **Implemented:** `pii` (see `egressveil/detectors/pii.py`).
  - Email addresses. Example, test and reserved domains, no-reply and `git@`
    addresses, and file names such as `icon@2x.png` are ignored.
  - International (`+`) and North-American phone numbers.
  - US SSNs. Invalid number ranges are excluded.
  - Payment cards. The number must pass the Luhn check and have a known
    issuer prefix.
  - IBANs. The number must pass the mod-97 check.
- **Implemented:** `internal_hostnames` (see
  `egressveil/detectors/hostnames.py`).
  - Hosts under the configured `internal_domains`.
  - Hosts under the conventional private suffixes `.internal`, `.corp`,
    `.intranet`, `.lan` and `.home.arpa`. You can turn these off.
    Well-known public development names such as `host.docker.internal` are
    excluded.
  - Optionally, RFC 1918 IPv4 addresses (`include_private_ips`).
  - By default, both PII and hostnames are redacted rather than blocked, so
    sessions keep working.

## 5. Policy actions

| Action | Behavior |
| --- | --- |
| `ALLOW` | Forward unchanged, record nothing |
| `REDACT` | Replace each span with `[EGRESSVEIL:<rule_id>:<8 hex>]`, then forward |
| `BLOCK` | Send nothing upstream. Return HTTP 400 in the provider's own error format (Anthropic or OpenAI) that names the rule IDs and JSON locations, never the values |
| `LOG_ONLY` | Forward unchanged and write an audit event |

The most restrictive action wins (`BLOCK` > `REDACT` > `LOG_ONLY` >
`ALLOW`). Overlapping matches are merged before redaction. By default,
secrets and tokens are blocked. Configuring `ALLOW` or `LOG_ONLY` for them
produces a warning.

**Signed content.** Anthropic `thinking` blocks carry a provider signature
over their exact text. That proves the provider generated the text and the
client didn't alter it, so re-sending it discloses nothing the provider
doesn't already have. Modifying the block would invalidate the request, and
blocking it would wedge the session on every later turn. Findings in signed
content are therefore recorded as `LOG_ONLY` with `"signed": true`.

Until v0.2.0 these findings were escalated to `BLOCK`. That changed when PII
detection was added, because model reasoning often mentions email
addresses.

**Placeholders.** The 8-hex suffix is an HMAC-SHA256 of the value under the
local key, so the same value always gets the same placeholder. That keeps the
conversation consistent for the model across turns and keeps provider prompt
caching effective. The placeholder reveals nothing about the value without the
key. Redacted bodies are re-serialized deterministically as ASCII JSON.
Requests with nothing to redact are forwarded byte-for-byte.

## 6. Fail-closed behavior (strict mode)

`gateway.mode: strict` is the default. **Implemented:** in strict mode the
gateway returns an error instead of forwarding when any of these is true:

| Condition | Reason code |
| --- | --- |
| Endpoint other than `POST /v1/messages[/count_tokens]` or a bodyless `GET`/`HEAD` | `unsupported_route` |
| Content type is not `application/json` | `unsupported_content_type` |
| Body is compressed (`Content-Encoding` other than identity) | `unsupported_content_encoding` |
| Invalid UTF-8 or JSON, a non-object root, or `NaN` | `invalid_json` |
| Duplicate JSON key | `duplicate_key` |
| Nesting deeper than 64 levels | `nesting_too_deep` |
| Base64 image or document (unless `gateway.allow_opaque_content: true`) | `opaque_content` |
| A detector raised an exception | `detector_error` |
| Body larger than `max_request_body_bytes`, declared or streamed (HTTP 413) | `body_too_large` |

`permissive` mode forwards uninspectable requests unchanged and writes an
audit event with `"inspected": false`. It still enforces policy on everything
it can inspect. Validation warns when it is enabled.

## 7. Safe audit logging

- **Implemented:**
  - Events are JSONL: timestamp, request ID, method, path (without the query
    string), outcome, reason, route, byte count, upstream status, duration,
    and for each finding the detector, rule ID, JSON location, action and a
    16-hex HMAC-SHA256 digest of the value.
  - Request bodies, headers, query strings and raw values are never written.
    Tests check this against real request flows.
  - `audit.include_raw_values: true` is rejected.
  - The digest key is 32 random bytes in `egressveil.key`, next to the audit
    log. It is created atomically with mode `0600` inside a `0700`
    directory. Windows has no POSIX modes, so there the files inherit the
    ACL of your profile directory.
  - The gateway opens the audit log at startup and refuses to start if it
    can't. If a write fails at runtime, it reports that on stderr and keeps
    serving.
  - Access logging is disabled, because access logs would record query
    strings.

## 7a. Allowlists and policy packs

- **Packs** (`balanced`, `redact`, `strict`, `audit`) set every category's
  action. `policy.rules` override a pack per detector, so a rule can never
  silently drop protection for the other categories. The `audit` pack warns
  at validation, and so does `ALLOW`/`LOG_ONLY` for secrets or tokens.
- **Allowlist entries** suppress findings by `digest`, `pattern` or `rule`.
  A digest entry lets you allow a known value without writing it into a
  config file. Because digests are keyed with the local key, a leaked
  config file doesn't help anyone guess or confirm a value. Patterns go
  through the same credential check as every other config value.
- **`extends`** files are size-capped and read with `safe_load`. Nesting is
  limited to five levels and cycles are rejected. The merged result is
  validated as one document.

## 8. No telemetry

EgressVeil contains no telemetry, analytics or update pings.
`telemetry.enabled: true` is rejected.

## 9. No automatic restoration into tool calls

**Implemented by design:** there is no un-redaction code path. A model, or a
prompt injection, therefore can't trick the gateway into putting a real
credential into a tool call or shell command. Any future restoration feature
will be opt-in, limited to display-only text, and documented separately.

## 10. Bounded bodies and streaming buffers

- `gateway.max_request_body_bytes`: default 16 MiB, allowed range 1 KiB to 256 MiB.
  **Implemented:** the server checks the declared `Content-Length` before
  reading and also enforces the limit while reading chunked bodies. Either
  way it returns `413 request_too_large`.
- `gateway.max_stream_buffer_bytes`: default 1 MiB, allowed range 1 KiB to 64 MiB.
  **Implemented:** responses are relayed in chunks of at most this size.
  The whole response is never held in memory.
- Upstream timeouts are 30 s to connect and 600 s of read inactivity. If the
  upstream fails mid-stream, the client connection is aborted rather than
  ended cleanly, so a truncated response is never mistaken for a complete one.

## 11. Configuration hygiene

- **Implemented:**
  - `yaml.safe_load` only, so YAML tags cannot construct objects
  - the config file is capped at 1 MiB
  - the schema rejects unknown keys
  - a config file containing credential-shaped strings is rejected
  - validation messages name the key path and the expected type, never the value
  - YAML syntax errors report only the line and column

## 12. Proxy bypass limitations

EgressVeil can protect only what passes through it. The
[threat model](threat-model.md) and [integrations](integrations.md) documents
list what bypasses it. Do not present EgressVeil as complete egress control.

## 13. Response inspection (optional)

- Off by default. When on, the gateway asks the upstream for uncompressed
  responses so it can inspect them without decoding a second copy.
- SSE streams are parsed event by event. Text under `delta` keys is
  concatenated before scanning, so values split across events are found.
  Scanning runs in 64 KiB windows with a 4 KiB overlap. JSON responses are
  parsed up to `max_request_body_bytes`; anything larger is marked
  `truncated` and not inspected.
- Findings are audited as `response_findings` with the `policy_action` that
  would apply. They never contain values.
- Responses are **never modified**. Rewriting a stream mid-flight could
  corrupt tool calls, and there is deliberately no un-redaction path (see
  section 9).
