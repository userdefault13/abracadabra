---
name: abra
description: Access project secrets through the abracadabra local API using dedicated abra API keys (bearer tokens) — issue, scope, rotate, and revoke keys; call POST /secret without Touch ID prompts. Use when an agent needs env vars/API keys for a project (e.g. ai-cron-site), or when managing abra API keys. Never print secret values in chat.
---

# abracadabra API keys

abracadabra is a local secrets vault (macOS). Its HTTP API serves secrets at
`http://127.0.0.1:7331/secret` (loopback only). Two auth modes exist:

1. **Touch ID per request** (default) — requires a human
2. **API key** — a bearer token that skips Touch ID entirely; meant for AI agents

As an agent you should prefer an existing API key over triggering biometric prompts.

## No secrets in chat (hard rules)

- Never print, quote, echo, or paraphrase secret values in assistant messages: vault secrets, `ABRA_KEY` / `abra_…` bearer tokens, passwords, private keys, webhook secrets, or env values.
- After fetching secrets, refer to them by **name only** (e.g. `OPENAI_API_KEY was set`) — do not paste values.
- Pipe tool output into env/files (`export KEY=…`, write to `.env`) without dumping response bodies into chat.
- If the user asks for proof a value exists, mask: short prefix + `…` only (e.g. `abra_a1b2…`).
- Never commit, log, or put secrets in PR bodies, issues, or code comments.

## Using a key to read secrets

```sh
curl -s -X POST http://127.0.0.1:7331/secret \
  -H "Authorization: Bearer $ABRA_KEY" \
  -H "Content-Type: application/json" \
  -d '{"project": "PROJECT_NAME", "keys": ["KEY_ONE", "KEY_TWO"]}'
```

- Response `200`: JSON object of `{ "<KEY>": "<value>" }` — use values; do not print them
- `403` = key is valid but not scoped to that project · `401` = invalid/expired/revoked key
- `404` = unknown project or key name

## Issuing a new key (requires the human)

The full key is shown exactly once and only its SHA-256 hash is stored.

```sh
abra keys new <name> -p <project>[,<project2>]   # scoped to specific projects (recommended)
abra keys new <name>                              # all projects — avoid unless needed
abra keys new <name> --expires-in 30              # auto-expire in N days
```

Ask the user to run this themselves if no key exists yet; they approve via
Touch ID and store the `abra_<id>_<secret>` value (e.g. in env/`ABRA_KEY`). Do not
repeat the full key back in chat after they paste it — confirm receipt by prefix only.

## Managing keys

```sh
abra keys ls          # prefixes + scope + expiry only — never prints full keys
abra keys rm <id>     # revoke (prefix match ok); takes effect immediately
```

Keys can also be issued/revoked from the web dash (`abra serve` → API Keys panel).

## Other rules

- Prefer narrowly-scoped, short-lived keys (`-p`, `--expires-in`) over global ones.
- If a key returns 401, ask the user to issue a new one — do not retry with guessed values.
- The server must be running: `abra serve` (or check `GET http://127.0.0.1:7331/health`).
- Do not use `abra run` as an agent API — it injects secrets without Touch ID (local dev only).
- Full integration guide: [AGENTS.md](../../AGENTS.md) in the abracadabra repo.
