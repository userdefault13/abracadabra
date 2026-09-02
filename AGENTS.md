# abracadabra — agent integration guide

abracadabra is a **local secrets vault** on macOS. Agents fetch env vars through a loopback HTTP API (`http://127.0.0.1:7331`) or the MCP server (`abra mcp`). This guide is for coding agents and the humans who supervise them.

**Platform:** macOS only (Touch ID + Keychain). **Network:** loopback by default (`abra serve`); optional `abra serve --lan` binds TLS on all interfaces (off-loopback `/secret` requires an API key). Vault LAN sync uses a separate short-lived `abra usb host` listener.

---

## Choose your auth mode

| Mode | Touch ID | Best for |
|------|----------|----------|
| **API key** (`Authorization: Bearer abra_…`) | Once at key issuance | Unattended agents, scripts, CI on the same machine |
| **Session grant** (`ttl` on `POST /secret`) | Once per app + project | Browser dapps / multi-step flows while `abra serve` runs |
| **MCP `get_secrets`** | Every read (or once if `ttl` set) | Human-in-the-loop coding agents (Cursor, Claude Desktop, etc.) |
| **`abra run`** | None | Local dev shell injection — **not** an agent API |

**Recommendation:** Prefer a scoped API key for unattended work. Use MCP when the human is at the keyboard and should approve each read (or use MCP `ttl` for a short silent window).

---

## Prerequisites

1. abracadabra installed: `npm install -g @userdefault/abracadabra` (macOS, Node 20+, Xcode CLT)
2. Vault initialized: `abra project new myproj` (first run creates `~/.abracadabra/`)
3. Server running for HTTP access: `abra serve`
4. Health check: `GET http://127.0.0.1:7331/health` → `{ "ok": true }`

---

## API key workflow (recommended for agents)

### 1. Human issues a key (Touch ID required)

```sh
abra keys new my-agent -p myproj              # scoped to one project (recommended)
abra keys new my-agent -p a,b --expires-in 30 # multiple projects, 30-day expiry
abra keys ls                                  # prefixes + scope only — never full keys
abra keys rm <id>                             # revoke immediately
```

The full key (`abra_<id>_<secret>`) is shown **once**. Store it in `ABRA_KEY` or your agent's env — never commit it.

Keys can also be created in the web dash: `abra serve --open` → **API Keys** panel.

### 2. Agent reads secrets (no Touch ID)

```sh
curl -s -X POST http://127.0.0.1:7331/secret \
  -H "Authorization: Bearer $ABRA_KEY" \
  -H "Content-Type: application/json" \
  -d '{"project": "myproj", "keys": ["OPENAI_API_KEY", "DATABASE_URL"]}'
```

- `200` — JSON `{ "<KEY>": "<value>", … }` — use values in env/files; **do not log or echo them**
- `401` — invalid, expired, or revoked key → ask human to issue a new one
- `403` — key valid but not scoped to that project
- `404` — unknown project or key name

---

## Session grants (HTTP, multi-step flows)

Add `"ttl"` (seconds) to skip repeated Touch ID prompts for the **same calling process + project**:

```sh
curl -s -X POST http://127.0.0.1:7331/secret \
  -H "Content-Type: application/json" \
  -d '{"project": "myproj", "keys": ["TOKEN"], "ttl": 300}'
```

- First request: Touch ID dialog (caller identified by PID + command line)
- Subsequent requests from the same app: silent until TTL expires (max 24h)
- Grants are in-memory — restarting `abra serve` revokes all
- `GET /grants` lists active grants · `DELETE /grants` revokes all

For browser dapps, set `ABRA_API_ORIGIN=https://yourapp` to restrict CORS.

---

## MCP setup

Register in your agent client (e.g. `.mcp.json`, `claude_desktop_config.json`):

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

See [`.mcp.json.example`](.mcp.json.example) in this repo.

### MCP tools

| Tool | Purpose |
|------|---------|
| `list_projects` | Discover project and key names (never values) |
| `get_secrets` | Touch ID gate → return values; optional `ttl` for silent re-reads |
| `list_grants` | List active MCP session grants (this process only) |
| `request_connection` | Check provider connection status + setup steps |
| `generate_wallet` | Store Foundry EVM wallet in vault |
| `generate_cloudflare_token` | Mint scoped Cloudflare token into vault |
| `generate_ssh_key` | Generate ed25519 keypair into vault |

### Parsing MCP responses

All tool results are JSON in `result.content[0].text`:

```js
const data = JSON.parse(result.content[0].text);
if (data.error || data.approved === false) {
  // handle denial or missing project/key
}
```

Example `get_secrets` call:

```json
{
  "project": "myproj",
  "keys": ["OPENAI_API_KEY"],
  "requestedBy": "my-cursor-agent",
  "ttl": 600
}
```

- `grantedVia: "touch-id"` — fresh approval
- `grantedVia: "session-grant"` — silent re-read within TTL

MCP grants are **separate** from HTTP grants (`abra serve` vs `abra mcp` are different processes).

---

## Security rules (hard)

- **Never** print, quote, echo, or paraphrase secret values in chat, logs, PRs, or issues
- After fetching secrets, refer to them by **name only** (e.g. `OPENAI_API_KEY was set`)
- Pipe values into env/files without dumping response bodies into conversation
- If proof is needed, mask: short prefix + `…` only (e.g. `abra_a1b2…`)
- Prefer narrowly-scoped, short-lived API keys over global ones
- Do **not** shell out to `abra run` from agents — it bypasses biometric gates

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Connection refused | `abra serve` not running | Start `abra serve` |
| `401` on `/secret` | Bad/expired/revoked API key | `abra keys ls` → issue new key |
| `403` on `/secret` | Key not scoped to project | Re-issue with `-p <project>` |
| `404` | Wrong project or key name | `list_projects` / `abra ls <proj>` |
| CORS preflight fails | Missing `Authorization` header allowance | Upgrade to abracadabra ≥ 1.0 |
| MCP always prompts Touch ID | No `ttl` on prior approval | Pass `ttl` on first `get_secrets` |
| `abra run` has no Touch ID | By design — local dev only | Use API keys or MCP for agents |

---

## Further reading

- [README.md](README.md) — full CLI, web dash, USB sync, connectors
- [skills/abra/SKILL.md](skills/abra/SKILL.md) — compact skill for agent clients
