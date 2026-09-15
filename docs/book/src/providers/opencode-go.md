# OpenCode Go

[OpenCode Go](https://opencode.ai/docs/go) is OpenCode's subscription to a catalog of coding
models. It serves those models over three protocol endpoints, so meka models it as three backends,
one per protocol:

| Backend | Protocol | Model families |
|---------|----------|----------------|
| `opencode-go` | OpenAI Chat Completions | GLM, Kimi, DeepSeek, MiMo, LongCat, Hy, Omen |
| `opencode-go-responses` | OpenAI Responses | Grok, GPT-5.6 Luna, Muse Spark |
| `opencode-go-messages` | Anthropic Messages | MiniMax, Qwen |

Which endpoint serves a model is OpenCode's routing: a request in the wrong shape is rejected. The
mapping changes with the catalog, so meka does not bundle a copy; OpenCode's [Go
docs](https://opencode.ai/docs/go) list it. `meka account add` offers all three backends, and
`meka profile add` suggests a current model for each (`kimi-k3`, `gpt-5.6-luna`, `minimax-m3`).

## Configuration

| Setting | Value |
|---------|-------|
| Account `backend` | `opencode-go`, `opencode-go-responses`, or `opencode-go-messages` |
| Default base URL | `https://opencode.ai/zen/go/v1` |
| Credential | API key from the [OpenCode console](https://opencode.ai/auth), kept in the store |
| Auth method | Bearer token (`Authorization: Bearer <key>`) |

The same key works for all three, so one subscription can be reached through three accounts:

```bash
meka account add oc-go --backend opencode-go
meka profile add coding --account oc-go --model kimi-k3
```

Add an account on the other two backends the same way, with the model that protocol serves.

### Config file

The commands write this for you (the key stays in the store, not here):

```toml
[accounts.oc-go]
backend = "opencode-go"

[profiles.coding]
account = "oc-go"
model   = "kimi-k3"
```

## The session header

OpenCode's API requires every request to carry a stable per-conversation id in
`x-opencode-session`, which the gateway uses to route a conversation's requests to one upstream and
to prompt-cache its prefix. Requests without it fail. meka sends the session's own id, the same id a
resume keeps. No configuration is needed.

## Usage

`meka account usage` shows the subscription's three dollar-budget windows, read from the gateway's
usage endpoint with the account's API key:

```console
$ meka account usage oc-go
Account usage
  5-hour (rolling)   [####------]  41% used  (resets in 3h 20m, 2026-09-19 15:00 -04:00)
  Weekly             [#---------]  12% used  (resets in 4d 23h, 2026-09-20 00:00 -04:00)
  Monthly            [######----]  58% used  (resets in 11d 12h, 2026-09-30 23:59 -04:00)
```

A window at 100% leaves the subscription rate-limited until it resets. When the account also has Zen
balance with **Use balance** enabled, requests fall back to it instead of failing.

## Supported models

Any model OpenCode Go serves on the protocol the backend speaks; the model string is forwarded
verbatim. OpenCode's Go docs list the catalog and its per-model endpoint, and
`GET https://opencode.ai/zen/go/v1/models` returns the ids. A profile's `context_window` defaults to
1M, as it does on every backend; state a smaller one on the profile if you want compaction to fire
earlier.
