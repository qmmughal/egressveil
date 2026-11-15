# Configuration reference

This page covers config schema `version: 1`, which is part of the public
contract (see [versioning.md](versioning.md)). A ready-to-copy file is in
[configs/egressveil.example.yaml](../configs/egressveil.example.yaml), and
`egressveil config validate` checks a file without ever printing its values.

**Discovery order:** `--config PATH`, then `$EGRESSVEIL_CONFIG`, then
`./egressveil.yaml`, then the user config directory
(`%APPDATA%\egressveil\`, `~/Library/Application Support/egressveil/` or
`~/.config/egressveil/`), and finally the built-in defaults.

**General rules:**
- Unknown keys are errors, so typos never weaken a setting.
- Credential-shaped values anywhere in a file are rejected.
- Files are limited to 1 MiB.

## Top level

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | integer | `1` | Schema version. Only `1` is accepted |
| `extends` | path or list of paths | none | Files merged before this one. `user` means your user config. Up to five levels deep, and cycles are rejected. See [policies.md](policies.md) |
| `gateway` | mapping | | See below |
| `providers` | mapping | | See below |
| `policy` | mapping | | See below |
| `detectors` | mapping | | See below |
| `audit` | mapping | | See below |
| `telemetry` | mapping | | See below |

## `gateway`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `listen_host` | string | `127.0.0.1` | Must be a loopback address unless `allow_non_loopback` is true |
| `listen_port` | integer 1–65535 | `8787` | |
| `mode` | `strict` \| `permissive` | `strict` | `strict` blocks requests it can't inspect (fails closed). `permissive` forwards them and flags them in the audit log |
| `allow_non_loopback` | boolean | `false` | Allows listening on a non-loopback address, with a warning |
| `max_request_body_bytes` | integer 1 KiB–256 MiB | `16777216` | Larger requests get `413` |
| `max_stream_buffer_bytes` | integer 1 KiB–64 MiB | `1048576` | Largest response chunk held in memory |
| `allow_opaque_content` | boolean | `false` | Forward images, audio and files that can't be inspected (warns) |
| `upstream_proxy` | `none` \| `env` \| `http(s)://host:port` | `none` | How the gateway reaches the provider. Credentials in the URL are rejected; use `env` instead |
| `inspect_responses` | boolean | `false` | Audit-only scanning of model responses |

## `providers.anthropic` and `providers.openai`

The Anthropic API is served at `/`, and OpenAI-compatible APIs at `/openai`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` for anthropic, `false` for openai | |
| `upstream_url` | `https://` URL | the official API | Must be an allowlisted host unless `allow_custom_upstream` is set |
| `allow_custom_upstream` | boolean | `false` | Allows a non-official host, with a warning |

## `policy`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pack` | `balanced` \| `redact` \| `strict` \| `audit` | `balanced` | Sets an action for every detector category |
| `default_action` | action | the pack's default | Used for categories that no rule covers |
| `rules` | list of rules | `[]` | Each rule overrides the pack for one detector |
| `allow` | list of allow entries | `[]` | Suppresses matching findings |

Actions are `ALLOW`, `REDACT`, `BLOCK` and `LOG_ONLY`.

**A rule** has these keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `detector` | `secrets` \| `tokens` \| `pii` \| `internal_hostnames` | The category the rule applies to |
| `action` | action | What to do with that category's findings |

**An allow entry** has exactly one of `digest`, `pattern` or `rule`:

| Key | Type | Meaning |
| --- | --- | --- |
| `digest` | 16 hex characters | One value, by its keyed digest from the audit log or `scan` output |
| `pattern` | regular expression, up to 512 characters | Searched in the matched value |
| `rule` | rule ID | Switches off one rule, for example `phone_nanp` |
| `detectors` | list of categories | Optional. Limits the entry to these categories |
| `comment` | string | Optional note. It is ignored |

## `detectors.<category>`

The categories are `secrets`, `tokens`, `pii` and `internal_hostnames`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | |
| `internal_domains` | list of domains | `[]` | `internal_hostnames` only. Your organisation's private domains |
| `include_common_internal_suffixes` | boolean | `true` | `internal_hostnames` only. Also flag hosts under `.internal`, `.corp`, `.intranet`, `.lan` and `.home.arpa` |
| `include_private_ips` | boolean | `false` | `internal_hostnames` only. Also flag RFC 1918 IPv4 addresses |

## `audit`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | |
| `path` | path | `~/.egressveil/audit.jsonl` | The format is described in [audit-log.md](audit-log.md). The digest key `egressveil.key` lives in the same directory |
| `include_raw_values` | boolean | `false` | Must be `false`. Raw values are never logged |

## `telemetry`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Must be `false`. EgressVeil has no telemetry |
