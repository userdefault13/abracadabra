---
name: abra
description: >-
  Operate abracadabra (local secrets vault) for agents — discover projects/keys,
  fetch secrets via API key or MCP without asking humans for passwords, issue/scope/revoke
  abra keys, health-check abra serve, connectors/keygen, USB/LAN sync, cartridge checkpoints.
  Use whenever an agent needs env vars, API tokens, wallets, or SSH keys from the vault,
  or when managing abracadabra. Never print secret values in chat.
---

# abracadabra — agent operations

Local secrets vault. Agents read secrets through **API keys** or **MCP** — not by
asking humans to paste passwords into chat.

**Default for unattended work:** scoped API key + `POST /secret` (no Touch ID).
**Default when human is at the keyboard:** MCP `get_secrets` with `ttl`.

Hard rule: **never ask the user for a secret value they already stored in abra.**
Discover the key name, fetch it, pipe into env/files. Humans only approve Touch ID /
issue a bearer key once.

## No secrets in chat (hard)

- Never print, quote, echo, or paraphrase vault values, `ABRA_KEY` / `abra_…` tokens,
  passwords, private keys, or env contents.
- After a fetch, say only that the **name** was set (e.g. `OPENAI_API_KEY was loaded`).
- Pipe tool/shell output into env or files — do not dump response bodies into chat.
- Proof if needed: short prefix + `…` only (e.g. `abra_a1b2…`).
- Never commit, log, or put secrets in PRs, issues, or code comments.
- Do **not** use `abra run` as an agent API (bypasses gates; local shell only).

## Bootstrap checklist

1. Health: `curl -s http://127.0.0.1:7331/health` → `{ "ok": true }`
   - If connection refused → ask human to run `abra serve` (or `abra serve --lan` for TLS LAN).
2. Prefer `$ABRA_KEY` already in the environment.
3. If missing: ask human to run `abra keys new <agent-name> -p <project>` once (Touch ID),
   store the shown `abra_…` value in `ABRA_KEY` — confirm by prefix only, never echo full key.
4. Discover names (never values): MCP `list_projects` or `abra ls` / `abra ls <project>`.

## Auth modes (pick one)

| Mode | Touch ID | Use when |
|------|----------|----------|
| **API key** `Authorization: Bearer $ABRA_KEY` | Once at issuance | Unattended agents, scripts, CI on this machine |
| **MCP `get_secrets`** (+ optional `ttl`) | Each read, or once per TTL | Interactive Cursor/Claude with human present |
| **HTTP session `ttl`** (no bearer) | First call per app+project | Browser dapps / multi-step same process |
| **`abra run`** | None | Human local shell only — **not for agents** |

Off-loopback (`abra serve --lan`): `/secret` **requires** an API key.

---

## 1. Fetch secrets (API key) — preferred

```sh
curl -s -X POST http://127.0.0.1:7331/secret \
  -H "Authorization: Bearer $ABRA_KEY" \
  -H "Content-Type: application/json" \
  -d '{"project": "PROJECT", "keys": ["KEY_ONE", "KEY_TWO"]}'
```

Safe load into the current shell without echoing values:

```sh
# writes KEY=value lines; do not cat the file into chat
eval "$(
  curl -s -X POST http://127.0.0.1:7331/secret \
    -H "Authorization: Bearer $ABRA_KEY" \
    -H "Content-Type: application/json" \
    -d '{"project": "PROJECT", "keys": ["KEY_ONE"]}' \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{const j=JSON.parse(d);for(const[k,v] of Object.entries(j)){if(k==="error")process.exit(1);console.log("export "+k+"="+JSON.stringify(v))}})'
)"
```

Or write a local `.env` (gitignored) the same way — never paste contents into chat.

**LAN (`abra serve --lan`):** use `curl --cacert ~/.abracadabra/lan-serve.pem` against
`https://$LAN_IP:7331/secret`. **Never `curl -k` / `--insecure`** — that enables MITM
theft of `ABRA_KEY` and secret payloads. Prefer loopback when the agent is on the same machine.

| Status | Meaning |
|--------|---------|
| `200` | Map of key → value — use silently |
| `401` | Bad/expired/revoked key → human re-issues |
| `403` | Key not scoped to that project |
| `404` | Unknown project or key name |

## 2. Fetch secrets (MCP)

Register once (`.mcp.json` / Claude Desktop):

```json
{
  "mcpServers": {
    "abracadabra": {
      "command": "abra",
      "args": ["mcp"]
    }
  }
}
```

| Tool | Purpose |
|------|---------|
| `list_projects` | Project + key **names** only |
| `get_secrets` | Values (Touch ID / session grant) |
| `list_grants` | Active MCP silent windows |
| `request_connection` | Provider status + setup steps for human |
| `generate_wallet` | Foundry wallet → vault |
| `generate_cloudflare_token` | Scoped CF token → vault |
| `generate_ssh_key` | ed25519 → vault |

`get_secrets` args example:

```json
{
  "project": "myproj",
  "keys": ["OPENAI_API_KEY"],
  "requestedBy": "cursor-agent",
  "ttl": 600
}
```

Parse `JSON.parse(result.content[0].text)`. On `error` / `approved: false`, stop — do not invent values.
Pass `ttl` on the first call so follow-ups in the same MCP process stay silent.

## 3. Manage API keys

```sh
abra keys new <name> -p <project>[,<p2>]   # scoped (recommended)
abra keys new <name> -p <project> --expires-in 30
abra keys ls                               # prefixes + scope only
abra keys rm <id>                          # revoke immediately
```

Human runs `keys new` (Touch ID). Agent may run `keys ls` / suggest `keys rm`.
Prefer narrow scope + expiry. Dash: `abra serve --open` → API Keys.

## 4. Discover & mutate vault (CLI)

Names only in chat:

```sh
abra project ls
abra ls                         # projects
abra ls <project>               # var names (secrets masked)
abra project new <name>         # create empty project
```

Store a value the **agent already generated** (do not ask the human to retype it):

```sh
printf '%s' "$GENERATED" | abra set <project> <KEY> --stdin
# or hidden prompt for the human if they must type once:
abra set <project> <KEY>
```

Read one value to stdout (Touch ID — prefer API key / MCP instead):

```sh
abra get <project> <KEY>        # agents: avoid; use POST /secret
```

## 5. Generate credentials into the vault

Prefer MCP tools when available. CLI equivalents:

```sh
abra keygen foundry <project> [--pay-to] [-n N]
abra keygen cloudflare <project>
abra keygen ssh <project>
abra connect <provider>         # human pastes provider credential once
abra issue <provider> <project> # mint provider vars into project
```

After generate/issue, fetch via `get_secrets` / API key — never ask the human for the new secret.

## 6. USB / LAN sync (multi-machine vault)

Not for day-to-day secret reads — for keeping two Macs' vaults aligned:

```sh
abra usb list [--lan]
abra usb backup / abra usb restore / abra usb sync
abra usb host                   # TLS + PIN + mDNS
abra usb peers
abra usb sync --lan [host:port] --pin <6-digit>
```

Dash USB panel supports the same. Sync-state: `~/.abracadabra/sync-state.json`.

## 7. Cartridge (cloud checkpoint)

```sh
abra cartridge ensure [wallet]
abra cartridge checkpoint              # metadata only
abra cartridge checkpoint --full       # passphrase-sealed BackupBundle
abra cartridge restore                 # from latest --full
abra cartridge status
```

`--full` still uses a passphrase seal — do not put that passphrase in chat logs.

## 8. Server

```sh
abra serve                      # loopback http://127.0.0.1:7331
abra serve --open               # + web dash
abra serve --lan                # HTTPS 0.0.0.0; writes ~/.abracadabra/lan-serve.pem
abra serve --lan --tls-cert c.pem --tls-key k.pem
# Clients: curl --cacert ~/.abracadabra/lan-serve.pem … — NEVER curl -k
```

`GET /health` · `GET /grants` · `DELETE /grants` · `POST /secret`

## Anti-patterns (do not)

- Asking the human “what’s the OpenAI key?” when it lives in abra
- Pasting `curl` response bodies or `.env` contents into chat
- Using `abra run` from an agent to skip auth
- Guessing/retrying API keys after `401`
- Committing `ABRA_KEY`, `.abrabak`, or vault files
- Exposing `/secret` without an API key on LAN
- Using `curl -k` / `--insecure` against `abra serve --lan`

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Connection refused | `abra serve` |
| `401` | `abra keys ls` → human issues new key |
| `403` | Re-issue key with `-p <project>` |
| `404` | `list_projects` / `abra ls <proj>` |
| MCP always Touch ID | Pass `ttl` on first `get_secrets` |
| LAN `/secret` without key | Use Bearer `abra_…` |

## Further reading

- Repo pitch for agents: [README.agents.md](../../README.agents.md)
- Repo guide: [AGENTS.md](../../AGENTS.md)
- Full CLI / security model: [README.md](../../README.md)
