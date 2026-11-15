# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
intends to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.0] - 2026-11-16

Path to 1.0, step 3: hardening.

### Security

- The upstream URL is now built from exactly the path that was inspected.
  Raw-socket tests found that an absolute-form request target
  (`POST http://other.host/v1/messages`) was inspected as `/v1/messages` but
  forwarded with a different path. The host never changed, but the
  differential is gone now. Requests whose encoded path doesn't match the
  inspected route, that contain encoded `/`, `.` or `\`, or whose final URL
  would leave the configured origin are refused with the new audit reason
  `ambiguous_path`.

### Added

- `egressveil service install|uninstall|status [--dry-run]`: run the gateway
  in the background at login, per user and without admin rights (Windows
  Task Scheduler, macOS launchd, Linux systemd `--user`). CI really installs
  and uninstalls it on Windows and Linux runners.
- `egressveil serve --log-file PATH`.
- CodeQL (`security-extended`) and OpenSSF Scorecard workflows, plus a
  CycloneDX SBOM attached to and attested with every release.
- Raw-socket HTTP edge-case tests: CL+TE smuggling, conflicting
  `Content-Length`, malformed chunked bodies, oversized headers, other
  transfer encodings, HTTP/1.0 without `Host`, absolute-form targets, encoded
  path tricks, pipelining, and short bodies.

## [0.7.0] - 2026-11-16

Path to 1.0, step 2: measured quality.

### Security

- Fuzzing found that text could be hidden from inspection inside
  structures that only *looked like* provider blobs, for example an object
  under `signature` or `encrypted_content`, extra fields in a
  `redacted_thinking` block, or fields beside a base64 `data` string. Only
  the blob *string* itself is now skipped; everything else is inspected.
  Agents don't build such requests, but strict mode must fail closed against
  crafted ones too.

### Added

- `scripts/benchmark.py` and `docs/benchmark.md`: 100% recall on 93
  labelled cases across 27 rules, and 0 secret or token false positives in
  29 MB of real code (the Python standard library plus popular packages).
- `scripts/perf.py` and `docs/performance.md`: about 1 ms added at 1 KB, 8 ms
  at 100 KB and 85 ms at 1 MB. Streaming runs at about 600 MB/s (14 MB/s
  with response inspection), and memory stays flat.
- CI quality gates: property-based fuzzing (Hypothesis), timing tests on
  adversarial input for every rule, recall and false-positive checks, and a
  24 MB soak test with a memory bound.

### Changed

- Detection is about **5x faster**: cheap substring pre-checks per rule,
  regexes that start with a character class, and case-folded matching
  instead of `IGNORECASE`.
- `phone_international` no longer matches decimals (`+35236450.6`), and
  `internal_hostnames` skips Python import paths (`from librt.internal
  import ...`).

## [0.6.0] - 2026-11-16

First step on the path to 1.0: frozen, documented and tested public
contracts.

### Added

- Every audit event now has `"schema_version": 1`. The JSON Schema is
  published as `egressveil/schemas/audit-event-v1.schema.json` (shipped in
  the package), and the health endpoint has `health-v1.schema.json`.
- Reference docs: `docs/configuration.md` (every key), `docs/cli.md` (every
  command, flag and exit code), `docs/audit-log.md` (every field, plus the
  guarantees) and `docs/versioning.md` (what is public, semver, deprecation).
- Contract tests: real gateway traffic covering every outcome is validated
  against the published schemas, and the tests fail if a config key or CLI
  command is undocumented.
- A "Path to 1.0" plan in `docs/roadmap.md`.

## [0.5.0] - 2026-11-16

EgressVeil moves from pre-alpha to **beta**. Every roadmap phase is
complete, and the integrations are verified against the live APIs. There are
no functional changes since 0.4.0.

### Changed

- The PyPI classifier is now `Development Status :: 4 - Beta`, and GitHub
  releases are published as the latest release rather than as pre-releases.
- The README status note now says what EgressVeil works with and detects,
  and links to the security limitations.

### Fixed

- `SECURITY.md` still said the current release "does not intercept or
  protect any traffic", which was true of 0.1 but not since 0.2. It now has a
  supported-versions table.
- `docs/integrations.md` still described Aider and OpenClaw as planned.

## [0.4.0] - 2026-11-16

Phase 3: policies, response inspection, and more agents.

### Added

- Policy packs: `balanced` (the default), `redact`, `strict` and `audit`.
- `policy.allow` allowlists, by keyed `digest` (no value ever goes in the
  file), `pattern` or `rule`, optionally limited to some `detectors`.
  `egressveil scan` now prints digests that you can copy into the allowlist.
- `extends:` to build on shared policy files, and `extends: user` for
  per-project configs that inherit your personal settings. Merging is per
  detector for rules, and lists are concatenated.
- Optional, audit-only response inspection
  (`gateway.inspect_responses: true`). It reassembles streamed deltas, so
  values split across SSE events are found, and scans in bounded windows.
- `egressveil setup <agent>` for `claude-code`, `aider`, `openclaw` and
  `cursor`.
- OpenClaw: setup snippet and a doctor check that `openclaw.json` points at
  the gateway.
- `egressveil run` warns when the running gateway uses a different
  configuration. The health endpoint reports a config fingerprint.
- `docs/policies.md`.

### Changed

- `policy.rules` now **override the pack per detector** instead of
  replacing the whole rule set. With the default pack this only makes
  things stricter: categories that a rules list leaves out keep the pack's
  action instead of falling back to `default_action`.
- Cursor is now documented as **not supported**. Its model requests come
  from Cursor's servers, which a loopback gateway can't see.

### Verified

- Claude Code 2.1.325 against the live API. It only uses `HEAD /api/hello`
  and `POST /v1/messages`. Blocks are shown to the user as is, and the
  `redact` pack sends only placeholders.

## [0.3.0] - 2026-11-16

Phase 2: Aider and broader detection.

### Added

- An OpenAI-compatible API adapter, mounted at `/openai`, covering Chat
  Completions, Responses, Completions and Embeddings. Blocks use OpenAI's
  error format. Base64 `data:` URIs, inline audio and files are treated as
  opaque, and `encrypted_content` is skipped.
- A `pii` detector: email, international and North-American phone numbers,
  US SSNs, payment cards (Luhn) and IBANs (mod-97), with false-positive
  filters for example and no-reply addresses and file names.
- An `internal_hostnames` detector: configured `internal_domains`, the
  private suffixes `.internal`, `.corp`, `.intranet`, `.lan` and
  `.home.arpa`, and optional RFC 1918 IPv4 addresses.
- `egressveil run -- <agent>`: starts the gateway if needed, sets
  `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and `OPENAI_API_BASE` (and
  `NO_PROXY` for loopback), runs the agent, passes back its exit code, and
  stops the gateway it started.
- `doctor`: an end-to-end self-test that sends a random canary credential
  which must be blocked locally, plus checks for the enabled providers and
  the proxy mode.
- `gateway.upstream_proxy`: `none` (the default), `env`, or an explicit proxy
  URL. Credentials in the config file are rejected.
- Verified with real clients: Aider 0.86.2 and the OpenAI and Anthropic
  Python SDKs, run against the live APIs.

### Changed

- Findings in provider-signed `thinking` content are now recorded as
  `LOG_ONLY` (`"signed": true`) instead of escalating to `BLOCK`. This content
  is provably provider-generated, and blocking it wedged sessions.
- `build_detectors()` takes hostname options, `Inspector.inspect_request()`
  takes a provider `adapter`, and `providers.anthropic` now exposes an
  `ADAPTER`. `providers.base` holds the shared parsing.
- EgressVeil is now on PyPI: `pip install egressveil` (or `pipx install egressveil`).

## [0.2.0] - 2026-11-16

First public release. EgressVeil is free and open source under the MIT
License. This release protects Claude Code's Anthropic API traffic from
leaking secrets and tokens. It is pre-alpha: see the README for coverage
limitations.

### Added: release and community

- A release workflow builds and smoke-tests each release, attaches signed
  build provenance, and creates the GitHub release. PyPI Trusted Publishing
  is ready but turned off until the project is registered on PyPI (see
  `docs/releasing.md`).
- Official support for Python 3.13 and 3.14. CI tests Python 3.11 to 3.14 on
  Linux, macOS and Windows.
- `SUPPORT.md`, `CODEOWNERS`, and install instructions using pipx or pip with
  the release wheel.

### Added: Phase 1, the Claude Code gateway

- `egressveil serve`: a local aiohttp gateway for the Anthropic Messages API
  (`/v1/messages`, `/v1/messages/count_tokens`), with streaming passthrough,
  bounded request bodies and stream chunks, verified TLS to an allowlisted
  upstream, no redirect following, and no use of environment proxies.
- An Anthropic request parser that inspects every string field, hardened
  against duplicate keys, `NaN` and deep nesting.
- `secrets` and `tokens` detectors with vendor, private-key, URL-credential,
  generic-assignment, JWT, bearer and Basic auth rules.
- A policy engine (the most restrictive action wins), keyed stable
  redaction placeholders, and escalation to `BLOCK` for signed `thinking`
  content and for URLs.
- Strict-mode fail-closed handling for unsupported routes, content types and
  encodings, invalid JSON, opaque images and PDFs, and detector errors.
  Permissive mode forwards these and flags them.
- A JSONL audit log with keyed digests and a `0600` key file. It never
  records bodies, headers, query strings or raw values.
- Host-header (DNS-rebinding) and browser-`Origin` rejection, and a local
  `/_egressveil/health` endpoint.
- `egressveil scan`: runs the detectors and policy over files or stdin.
- `doctor` detects a running gateway and lists the active detectors.
- Config option `gateway.allow_opaque_content`.
- Runtime dependency: `aiohttp`.

### Added: Phase 0, the foundation

- Project scaffold: `src/` layout, Hatchling packaging, MIT license.
- CLI commands: `egressveil version`, `egressveil config validate` and
  `egressveil doctor`.
- A strict YAML configuration schema with secure defaults enforced at
  validation: loopback-only listener, https allowlisted upstreams, strict
  mode, no raw-value audit logging, and no telemetry.
- Secret-safe validation output, and rejection of config files that contain
  credential-shaped values.
- Documentation: architecture, threat model, security design, integrations
  and roadmap.
- CI: Ruff, strict mypy, and pytest on Python 3.11 and 3.12 across Linux,
  macOS and Windows; a build check; and pip-audit dependency auditing.

[Unreleased]: https://github.com/qmmughal/egressveil/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/qmmughal/egressveil/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/qmmughal/egressveil/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/qmmughal/egressveil/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/qmmughal/egressveil/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/qmmughal/egressveil/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/qmmughal/egressveil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qmmughal/egressveil/releases/tag/v0.2.0
