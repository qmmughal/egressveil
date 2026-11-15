# Integrations

> **Nothing on this page works yet.** It describes how each agent is expected
> to be routed through EgressVeil once the gateway ships, and what will remain
> **outside** its coverage. Agent behavior changes between versions, so check
> it against each tool's current documentation before relying on it.

## Coverage model

EgressVeil inspects **LLM API requests that an agent sends to the gateway's
local address**. It does this by acting as the agent's API base URL. EgressVeil
is not a system-wide proxy and does not intercept TLS.

For every agent, the following are **not covered**:

- shell or terminal commands the agent runs (`curl`, `git`, package managers),
- web fetch and web search tools,
- MCP servers and plugins, which make their own connections,
- vendor telemetry, update checks and authentication flows,
- any SDK or client that ignores the base-URL setting.

## Claude Code (initial priority, Phase 1)

- **Routing:** set `ANTHROPIC_BASE_URL` to the gateway, for example
  `http://127.0.0.1:8787`. Claude Code then sends its Anthropic Messages API
  calls to EgressVeil, and EgressVeil forwards them to `api.anthropic.com`.
- **Credentials:** Claude Code keeps its own credentials. EgressVeil passes
  the auth header through unchanged and never stores or logs it.
- **Inspected:** system prompt, messages, tool definitions, and tool results
  as they appear in Messages API requests.
- **Not inspected:** the commands that Claude Code tools run, web fetches,
  MCP server traffic, and any non-API connections.
- **Doctor:** `egressveil doctor` reports whether `claude` is on `PATH` and
  whether `ANTHROPIC_BASE_URL` points at the gateway. It never prints the
  variable's value.

## Aider (initial priority, Phase 2)

- **Routing:** Aider talks to providers through LiteLLM. The plan is to
  point the provider base URL at the gateway, using `ANTHROPIC_BASE_URL` for
  Anthropic models and `--openai-api-base` or the `OPENAI_API_BASE` /
  `OPENAI_BASE_URL` variables for OpenAI-compatible models.
- **Requires:** the OpenAI-compatible parser planned for Phase 2. Anthropic
  routing becomes available with Phase 1.
- **Not inspected:** Aider's git operations, `/web` scraping, shell
  commands, and other providers that aren't routed through the gateway.

## OpenClaw (future, Phase 3)

Not supported yet. The routing mechanism will be documented once the
integration has been researched and tested.

## Cursor (limited and experimental)

Cursor is expected to be the most limited integration:

- In typical configurations Cursor's model requests go through Cursor's own
  backend, not directly from your machine to the model provider. A local
  base-URL gateway therefore can't see most of this traffic.
- Some custom-API-key or base-URL options may route specific requests
  differently, but those requests may still go through vendor infrastructure.
  Coverage is expected to be partial.
- EgressVeil will **not** use TLS interception to work around this.

Any Cursor support will be labeled experimental and will document exactly
which request types are covered. Treat Cursor as **not protected** unless a
release says otherwise.

## Verifying routing

After Phase 1 you will be able to confirm that traffic is routed by watching
the audit log while the agent runs. Until then, `egressveil doctor` reports
only static prerequisites.
