# Integrations

> **Status:** Claude Code and Aider are available and verified against the
> live APIs. OpenClaw is available but its configuration is not yet verified
> end to end. Cursor is not supported. Agent behavior changes between
> versions, so check it against each tool's current documentation before
> relying on it.

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

## Claude Code (available)

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
- **Verified with Claude Code 2.1.325** (`egressveil run -- claude -p ...`
  against the live API, with a dummy key):
  - The only routes it used were `HEAD /api/hello` (a connectivity check,
    forwarded) and `POST /v1/messages`. Strict mode doesn't break Claude
    Code.
  - Clean prompts were forwarded, and Anthropic's real authentication error
    came back.
  - A prompt containing a token was blocked locally, and Claude Code showed
    EgressVeil's message as is.
  - With the `redact` pack, the token, an email address and an internal
    hostname all reached Anthropic only as placeholders.
- **Not yet verified live:** the tool-result path, for example the agent
  reading `.env` itself, needs a real API key, because the model has to
  answer before a tool runs. It is covered by the end-to-end tests.
- **Doctor:** `egressveil doctor` reports whether the gateway is running,
  whether `claude` is on `PATH`, and whether `ANTHROPIC_BASE_URL` points at
  the gateway. It never prints the variable's value.

## Aider (available)

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

## OpenClaw (available, configuration documented)

[OpenClaw](https://docs.openclaw.ai/concepts/model-providers/custom-providers)
reads its model providers from `models.providers` in `~/.openclaw/openclaw.json`
(JSON5). The base URL of a built-in provider such as `anthropic` can be
overridden, and custom OpenAI-compatible providers take a `baseUrl` that
includes `/v1`. OpenClaw trusts the exact configured loopback origin, so no
`allowPrivateNetwork` setting is needed.

`egressveil setup openclaw` prints the snippet for your configuration:

```json5
{
  models: {
    providers: {
      anthropic: { baseUrl: "http://127.0.0.1:8787" },
      // only when providers.openai.enabled: true in EgressVeil
      "egressveil-openai": { baseUrl: "http://127.0.0.1:8787/openai/v1", api: "openai-completions" },
    },
  },
}
```

- Keep your existing `apiKey` settings, then restart the OpenClaw gateway.
- `egressveil doctor` checks whether `openclaw.json` contains a provider
  `baseUrl` pointing at the gateway. It never prints the file.
- **Not covered:** OpenClaw's own tools (browsing, shell, messaging
  channels) and any provider whose `baseUrl` doesn't point at EgressVeil.
- **Verification status:** the configuration follows OpenClaw's
  documentation. It has **not** yet been verified end to end with a running
  OpenClaw installation. Reports are welcome.

## Cursor (not supported)

The Phase 3 assessment concluded that Cursor **cannot** be protected by a
local gateway:

- Cursor builds prompts and sends model requests from **Cursor's own
  servers**, including when you set "Override OpenAI Base URL". Those
  servers can't reach `127.0.0.1`. That's why guides for custom endpoints in
  Cursor ask for a publicly reachable HTTPS URL
  ([Cursor forum](https://forum.cursor.com/t/problem-reaching-openai-error-on-a-local-model-with-overriden-base-url/3975),
  [LiteLLM's Cursor guide](https://docs.litellm.ai/docs/tutorials/cursor_integration)).
- Exposing EgressVeil to the internet through a tunnel would contradict its
  loopback-only design. It also wouldn't help: by the time a request
  reached the gateway, your code would already have passed through Cursor's
  backend.
- EgressVeil will not use TLS interception to work around this.

`egressveil setup cursor` and `egressveil doctor` both say so plainly. Treat
Cursor as **not protected** by EgressVeil.

## Verifying routing

- `egressveil doctor` runs an end-to-end **self-test** against the running
  gateway. It sends a random canary credential that must be blocked locally,
  so the test never reaches the provider.
- Each request the agent makes appears as one line in the audit log. If an
  agent's requests don't appear there, they aren't going through
  EgressVeil.
