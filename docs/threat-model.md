# Threat Model

> Status: draft for Phase 0. This model will be revisited before each phase
> ships.

## Assets

1. **Secrets in the workspace**: API keys, cloud credentials, private keys,
   database URLs, session tokens.
2. **Personal data**: customer records, emails, phone numbers and similar
   data in code, fixtures, logs or prompts.
3. **Internal topology**: internal hostnames, domains and service names.
4. **The audit log itself**, which must not become a second copy of the
   secrets.

## In scope

| Threat | Example | Planned mitigation |
| --- | --- | --- |
| **Accidental disclosure** to an LLM provider | The agent reads `.env` and includes it in context | Detection plus `BLOCK` / `REDACT` |
| Disclosure through **tool results** | Output of `cat config.yml` is sent back as a tool result | Parsers inspect tool-result fields, not only user messages |
| **Misdirected upstream** | Config or environment points the agent at a look-alike host | Per-provider https host allowlist |
| **Gateway exposure** on the LAN | The gateway listens on `0.0.0.0` and other hosts relay through it | Loopback-only default, with an explicit opt-in that warns |
| **Secrets leaking through logs** | The audit log or an error message contains the matched value | Findings store offsets only, config rejects raw-value logging, and errors name locations, not values |
| **Resource exhaustion** | A huge or endless request or stream exhausts memory | Hard body and stream-buffer limits |
| **Silent fail-open** | An unknown API shape passes through uninspected | Strict mode blocks uninspectable requests |
| **Redaction reversal into actions** | The model echoes a placeholder and EgressVeil restores the real secret into a shell tool call | Secrets are never automatically restored into tool calls |
| **Unsafe config parsing** | A YAML tag executes code | `yaml.safe_load` only, a size cap, and a strict schema |

## Out of scope

EgressVeil does **not** defend against:

- **Traffic that doesn't go through the gateway.** This includes agent shell
  commands (`curl`, `git push`, `pip install`), web fetch or search tools, MCP
  servers, IDE extensions, vendor telemetry, and any client that ignores the
  configured base URL.
- **Vendor-mediated traffic** that you can't redirect locally, such as models
  served through a vendor's own backend (see Cursor in
  [integrations.md](integrations.md)).
- **A malicious local user or malware** running under the same account. It
  can stop the gateway, change config, or talk to the internet directly.
- **A compromised or malicious LLM provider** acting on data that was allowed
  through.
- **Perfect detection.** Heuristic detectors have false negatives. Encoded,
  split or obfuscated secrets can evade them.
- **Response-side attacks** such as prompt injection in model output. This is
  planned as a separate, later concern.

## Trust boundaries

```text
[ Agent process ] --(loopback HTTP)--> [ EgressVeil ] --(TLS)--> [ Provider API ]
      untrusted input                   trusted, local                 external
```

- Request content from the agent is **untrusted input** to EgressVeil and
  must be parsed defensively.
- The config file is trusted, but it is still validated strictly.
- EgressVeil never needs, stores or logs the user's provider credentials.

## Assumptions

- The user has configured the agent to use the gateway, and `egressveil
  doctor` helps verify this.
- The host OS and Python runtime are not compromised.
- Provider API schemas change over time. Strict mode turns an unrecognized
  schema into a visible failure instead of a silent bypass.
