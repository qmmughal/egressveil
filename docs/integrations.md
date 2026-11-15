# Integrations

> **Status:** the Claude Code integration (the Anthropic Messages API) is
> available as pre-alpha. Everything else on this page is planned. Agent
> behavior changes between versions, so check it against each tool's current
> documentation before relying on it.

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

## Claude Code (available, pre-alpha)

```bash
egressveil serve                                   # terminal 1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787    # terminal 2 (PowerShell: $env:ANTHROPIC_BASE_URL = "...")
claude
```

- **Routing:** with `ANTHROPIC_BASE_URL` set to the gateway, Claude Code
  sends its Anthropic Messages API calls to EgressVeil. EgressVeil inspects
  them and forwards them to `api.anthropic.com`.
- **Credentials:** Claude Code keeps its own credentials. EgressVeil passes
  the auth header through unchanged and never stores or logs it.
- **Inspected:** every string in `POST /v1/messages` and
  `/v1/messages/count_tokens` request bodies, including the system prompt,
  messages, tool definitions, `tool_use` inputs and `tool_result` content,
  plus the query string.
- **Blocked in strict mode:** any other endpoint that has a request body,
  and images or PDFs (unless `gateway.allow_opaque_content: true`). If
  Claude Code shows an EgressVeil `unsupported_route` error, please open an
  issue with the method and path from the audit log.
- **Usability:** a blocked value stays in the conversation history, so
  later turns are blocked too. Start a new session, or use `REDACT` for
  `secrets` and `tokens` (see the README).
- **Not inspected:** the commands that Claude Code tools run, web fetches,
  MCP server traffic, and any non-API connections.
- **Verification so far:** the gateway is tested end to end against a mock
  upstream that covers streaming, errors, redirects and compression. It has
  also been smoke-tested against the live `api.anthropic.com` endpoint (TLS,
  forwarding and the error passthrough). It has **not yet** been validated
  across many Claude Code versions and workflows.
- **Doctor:** `egressveil doctor` reports whether the gateway is running,
  whether `claude` is on `PATH`, and whether `ANTHROPIC_BASE_URL` points at
  the gateway. It never prints the variable's value.

## Aider (available, pre-alpha)

```bash
egressveil run -- aider --model anthropic/claude-sonnet-5-5
egressveil run -- aider --model openai/gpt-5      # needs providers.openai.enabled: true
```

- **Routing:** Aider talks to providers through LiteLLM. `egressveil run`
  sets `ANTHROPIC_BASE_URL` to the gateway and, when the OpenAI provider is
  enabled, sets `OPENAI_API_BASE` / `OPENAI_BASE_URL` to
  `http://127.0.0.1:8787/openai/v1`. To configure it by hand, pass
  `--openai-api-base http://127.0.0.1:8787/openai/v1` instead.
- **Inspected:** chat messages, including file contents that Aider adds to
  the chat, repository-map text, and tool calls and results.
- **Verified:** Aider 0.86.2 was run through `egressveil run` against the
  live OpenAI and Anthropic APIs with dummy keys. Both requests were routed,
  inspected and forwarded, and both providers' real errors came back. The
  official OpenAI and Anthropic Python SDKs were checked the same way,
  including a local block in each provider's error format.
- **Other OpenAI-compatible endpoints:** the gateway's OpenAI upstream is
  `api.openai.com` by default. For another OpenAI-compatible service, set
  `providers.openai.upstream_url` and `allow_custom_upstream: true`.
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

- `egressveil doctor` runs an end-to-end **self-test** against the running
  gateway. It sends a random canary credential that must be blocked locally,
  so the test never reaches the provider.
- Each request the agent makes appears as one line in the audit log. If an
  agent's requests don't appear there, they aren't going through
  EgressVeil.
