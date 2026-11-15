# Policies, allowlists and per-project configuration

## Policy packs

A pack sets the action for every detector category at once. Pick one with
`policy.pack`, then override individual categories with `policy.rules`.

| Pack | secrets | tokens | pii | internal_hostnames | Use it when |
| --- | --- | --- | --- | --- | --- |
| `balanced` (default) | BLOCK | BLOCK | REDACT | REDACT | Most users |
| `redact` | REDACT | REDACT | REDACT | REDACT | Interactive Claude Code sessions. A redacted value never wedges the session the way a blocked one does |
| `strict` | BLOCK | BLOCK | BLOCK | BLOCK | Regulated environments; nothing sensitive is rewritten and sent |
| `audit` | LOG_ONLY | LOG_ONLY | LOG_ONLY | LOG_ONLY | Trying EgressVeil out: see what *would* happen without changing traffic |

```yaml
policy:
  pack: redact
  rules:                      # override one category on top of the pack
    - detector: secrets
      action: BLOCK
```

`policy.rules` entries override the pack **per detector**. They don't
replace the whole rule set. `default_action` only applies to detector
categories that no rule covers.

## Allowlists

Allowlist entries suppress findings you have checked and accept. Each entry
has exactly one of these keys:

| Key | Matches | Example |
| --- | --- | --- |
| `digest` | One specific value, by the 16-hex keyed digest shown in the audit log and in `egressveil scan` output | `- digest: 9f2c4be01a7d33e8` |
| `pattern` | A regular expression searched in the matched value | `- pattern: '@acme\.com$'` |
| `rule` | A whole rule, by rule ID | `- rule: phone_nanp` |

Any entry can be limited to some categories with `detectors: [pii]`. You can
add a `comment:` for the next reader.

```yaml
policy:
  allow:
    - digest: 9f2c4be01a7d33e8      # the documented sandbox key in tests/fixtures
      comment: public sandbox key, safe to share
    - pattern: '@acme\.com$'
      detectors: [pii]
    - rule: private_ipv4
```

**Why digests?** They let you allow a known false positive without writing
the value itself into a config file. That matters because config files get
committed and shared, and `config validate` rejects credential-shaped strings
anywhere in them, including allowlist patterns. Digests are keyed with your
machine's `egressveil.key`, so they only match on the machine that produced
them. For allowlists you share with a team, use `pattern` or `rule` entries.

To find a digest:

```console
$ egressveil scan tests/fixtures/sandbox.env
tests/fixtures/sandbox.env:2:12: BLOCK    secrets/stripe_secret_key  digest=9f2c4be01a7d33e8
```

## Sharing policies: `extends`

A config file can build on other files:

```yaml
# egressveil.yaml
extends:
  - ../security/egressveil-team.yaml     # relative to this file
  - ~/.config/egressveil/extra.yaml
policy:
  rules:
    - detector: pii
      action: BLOCK
```

The files are merged in order, and this file is applied last.

- Mappings merge key by key.
- `policy.rules` merge per detector.
- Other lists (allowlists, `internal_domains`) are concatenated.
- `extends` may nest up to five levels deep. Cycles are rejected.
- Every merged file is validated as one document, credential check included.

## Per-project overrides

Configuration is discovered in this order: `--config`, then
`$EGRESSVEIL_CONFIG`, then `./egressveil.yaml`, then your user config. A
project can therefore carry its own `egressveil.yaml` and build on your
personal settings with the special `user` entry:

```yaml
# my-project/egressveil.yaml
extends: user
detectors:
  internal_hostnames:
    internal_domains: [payments.corp.example.com]
```

Run your agent from the project directory with `egressveil run -- claude`.
If a gateway started with a *different* configuration is already running,
`egressveil run` warns you, because it can't change the configuration of a
running gateway. Stop that gateway, or use a different `gateway.listen_port`
per project.

## Response inspection

```yaml
gateway:
  inspect_responses: true
```

When this is on, model responses are scanned with the same detectors,
allowlist and policy, and findings are written to the audit log under
`response_findings`.

- Responses are **never modified**, so findings are recorded with action
  `LOG_ONLY` plus the `policy_action` that would have applied to a request.
- Streaming responses are reassembled from their `delta` events before
  scanning, so a value split across events is still found. Scanning runs in
  bounded windows, so memory use stays flat.
- To inspect without decompressing a second copy, the gateway asks the
  upstream for uncompressed responses (`Accept-Encoding: identity`) while
  this is on. That costs some bandwidth.
