# ✦ abracadabra

Terminal vault for env vars & passwords, with a biometric-gated local API so
dapps and scripts can pull secrets on demand — and a subprocess wrapper that
injects them invisibly into any command.

```
┌─────────────┐     ┌──────────────────────────────────┐
│  Ink TUI    │────▶│  Core (TypeScript)               │
│  (abra)     │     │  vault CRUD · crypto · unlock    │
└─────────────┘     └──────┬───────────────┬───────────┘
                           │               │
              ┌────────────▼───┐   ┌───────▼─────────────┐
              │ Vault file     │   │ Local HTTP API      │
              │ AES-256-GCM    │   │ 127.0.0.1:7331      │
              │ ~/.abracadabra │   │ POST /secret        │
              └────────────────┘   │ → Touch ID gate     │
                                   └───────┬─────────────┘
                                           │
┌──────────────────────────────────────────▼─────────────┐
│ abra run --project myproj -- npx wrangler deploy       │
│ (spawns the command with vars injected into its env)   │
└─────────────────────────────────────────────────────────┘
```

## Setup

Requires Node 20+ and macOS (Touch ID).

```sh
npm install
npm run build
npm run setup   # compiles the Touch ID helper (swiftc → vendor/auth-helper)
npm link        # installs `abra` on your PATH
```

## Quick start

**Terminal:**

```sh
abra project new myproj        # create a project
abra set myproj MY_API_KEY     # hidden input — stored AES-256-GCM encrypted
abra ls myproj                 # list vars (secrets masked)
abra get myproj MY_API_KEY     # reveal value → approve Touch ID
abra run myproj -- ./deploy.sh # inject all vars into any command
```

**Interactive TUI:**

```sh
abra                           # arrow keys, enter to select; full var editor
```

**Web dashboard:**

```sh
npm run web:build              # one-time build of the Svelte UI
abra serve --open              # serves API + dash at http://127.0.0.1:7331/
```

## CLI

| Command | Purpose |
|---|---|
| `abra` | Launch the interactive TUI |
| `abra project new <name>` | Create a project |
| `abra project rm <name>` / `project ls` | Delete / list projects |
| `abra ls [project]` | List projects, or vars in a project (secrets masked) |
| `abra set <proj> <KEY>` | Add/update a var — hidden input by default; `--visible`, `--no-secret`, `--stdin` flags available |
| `abra get <proj> <KEY>` | Print value to stdout (**Touch ID required**) |
| `abra rm <proj> <KEY>` | Delete a var |
| `abra keygen foundry <proj>` | Generate EVM wallet(s) via Foundry (`--pay-to`, `-n`) |
| `abra run [-p proj] [-k K1,K2] -- <cmd…>` | Run command with vars injected into env |
| `abra env <proj> [-k K1,K2]` | Print `export` lines for `eval $(…)` — Touch ID gated |
| `abra serve [--port 7331] [--open]` | Start the local biometric-gated API + web dash |

### Injecting secrets into a deploy

```sh
# every var from the project
abra run myproj -- npx wrangler deploy

# only specific keys
abra run -p myproj -k CLOUDFLARE_API_TOKEN,CLOUDFLARE_ACCOUNT_ID -- npx wrangler deploy
```

Secrets are never echoed to your terminal — you'll see only key names.

### Shell eval mode

```sh
eval $(abra env myproj)                # export all vars
eval $(abra env -k KEY1,KEY2 myproj)   # subset only
```

Prints `export` statements (properly single-quote-escaped), Touch ID gated like
`get`. Vars live in your current shell afterwards.

## Local API

```sh
abra serve
```

```sh
curl -X POST http://127.0.0.1:7331/secret \
  -H 'Content-Type: application/json' \
  -d '{"project": "myproj", "keys": ["CLOUDFLARE_API_TOKEN"]}'
```

On each request abracadabra:

1. Resolves **who is asking** (PID + full command line of the caller)
2. Pops a Touch ID dialog naming them:
   *abracadabra: curl (pid 81318) requests CLOUDFLARE_API_TOKEN from "myproj"*
3. Returns the values on approval (`403` on deny/timeout)

Other responses: `400` bad body · `404` unknown project/key · loopback-only.
CORS is enabled for browser dapps; restrict it with `ABRA_API_ORIGIN=https://yourapp`.

### Session grants (Touch ID once, then silent)

Add `"ttl"` (seconds) to the request: after one approval, the same app gets
**silent access to that project** until the TTL expires — no repeated dialogs
for multi-step deploys or polling dapps.

```sh
curl -X POST http://127.0.0.1:7331/secret \
  -H 'Content-Type: application/json' \
  -d '{"project": "myproj", "keys": ["CLOUDFLARE_API_TOKEN"], "ttl": 300}'
```

- Grants are keyed on **app identity + project**; a different program still
  needs its own approval
- Max TTL is 24h; grants live in memory only — restarting `abra serve` revokes all
- `GET /grants` lists active grants · `DELETE /grants` revokes them all

Example dapp client:

```js
const res = await fetch("http://127.0.0.1:7331/secret", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ project: "myproj", keys: ["CLOUDFLARE_API_TOKEN"] }),
});
if (!res.ok) throw new Error("user denied access");
const { CLOUDFLARE_API_TOKEN } = await res.json();
```

## Third-party connections

Connect provider accounts once, then issue their credentials into any project.

Supported providers: **cdp** (Coinbase Developer Platform) · **cloudflare** · **vercel**

```sh
abra connect cdp                 # opens portal, stores creds encrypted (hidden input)
abra connect cloudflare          # CLOUDFLARE_API_TOKEN + ACCOUNT_ID
abra connect vercel              # VERCEL_TOKEN (+ optional ORG_ID / PROJECT_ID)
abra connections                 # list connected accounts
abra issue cloudflare myproj     # Touch ID gate → provider vars into project
abra disconnect cloudflare
```

> **CDP note:** Coinbase Developer Portal API keys are created in the Portal UI
> — there is no public endpoint/OAuth flow to mint them programmatically (the
> CDP API v2 spec has no key-management endpoints). abracadabra therefore
> stores your admin key once and provisions it per-project; when Coinbase
> ships a create-key API, `issue` becomes an API call without CLI changes.

Then run your app with everything injected:

```sh
cd ~/Dev/ai-cron-site
abra run ai-cron-site -- pnpm dev        # or wrangler dev / vercel dev, etc.
```

## Web dash (Svelte)

A local management UI served by `abra serve`:

```sh
npm run web:build    # one-time build of the Svelte app into web/dist
abra serve           # → http://127.0.0.1:7331/
```

- Browse projects & keys with masked values; reveal/copy/edit/delete/add vars
- Connections panel (list/disconnect providers) and session-grants panel (live TTLs, revoke)
- **Every sensitive action fires a Touch ID prompt** on the server side — the
  browser never gets values unless you fingerprint
- Dev mode: `npm run web:dev` (Vite on :5173 proxying to :7331)

### Local wallet generation (Foundry)

Generate fresh EVM wallets with Foundry's `cast` and store them straight into
a project — private keys encrypted, never printed:

```sh
abra keygen foundry myproj               # EVM_ADDRESS + EVM_PRIVATE_KEY
abra keygen foundry myproj --pay-to      # also sets PAY_TO_ADDRESS (x402)
abra keygen foundry myproj -n 5          # multiple wallets (_1 … _n suffixes)
```

## MCP server (for AI agents)

Agents working on a project can request env vars through the
[Model Context Protocol](https://modelcontextprotocol.io). Every `get_secrets`
call pops a Touch ID dialog on your machine naming the agent — nothing is
returned unless you approve.

Register it with your agent client:

```jsonc
// e.g. .mcp.json / opencode.json / claude_desktop_config.json
{
  "mcpServers": {
    "abracadabra": { "command": "abra", "args": ["mcp"] }
  }
}
```

### Tools

| Tool | Args | Returns |
|---|---|---|
| `list_projects` | — | `{ projects: { "<name>": { "<KEY>": { secret } } } }` — key names only, never values |
| `get_secrets` | `{ project, keys[], ttl?, requestedBy? }` | Touch ID gate → `{ approved: true, vars: { "<KEY>": "<value>" }, grantedVia: "touch-id" }` |
| `generate_wallet` | `{ project, payTo? }` | Foundry wallet stored encrypted → `{ wallets: [{ address, varSuffix, payToSet }] }` |

### How an agent requests a var

```jsonc
// 1. discover what exists
{ "tool": "list_projects", "arguments": {} }

// 2. request specific keys (user sees: "abracadabra: my-agent (MCP agent)
//    requests CLOUDFLARE_API_TOKEN from 'ai-cron-site'")
{
  "tool": "get_secrets",
  "arguments": { "project": "ai-cron-site", "keys": ["CDP_API_KEY_ID"], "requestedBy": "my-agent" }
}
```

Response arrives as JSON text in `result.content[0].text`:

```json
{
  "approved": true,
  "grantedVia": "touch-id",
  "vars": { "CDP_API_KEY_ID": "organizations/…" },
  "note": "treat these values as secrets; do not log or echo them"
}
```

Denial/timeout → `isError: true` with `{ approved: false }`. Missing keys or
projects also return structured errors — agents should parse
`JSON.parse(result.content[0].text)` and check `.error`.

## Security model

- Vault is a single file at `~/.abracadabra/vault.enc`, AES-256-GCM encrypted;
  master key lives in the macOS Keychain (`abracadabra-master-key`)
- Vault writes are atomic (tmp + rename) with `0600` perms; directory is `0700`
- `abra get` and every API request require per-use biometric approval
- The API identifies the requesting process so you always know who's asking
- Caveat: Keychain items created via the `/usr/bin/security` CLI can be read by
  any local process that shells out to it; the LAContext prompt is the primary
  gate. A Rust rewrite would use the Security framework directly to close this.

## Development

```sh
npm run dev          # tsx src/index.ts … (no build step)
npm run typecheck    # tsc --noEmit
npm run web:build    # build the Svelte dash into web/dist
npm run web:dev      # Vite dev server for the dash on :5173 (proxies to :7331)
node demo/demo.sh    # end-to-end demo: vault → API → dapp client → run injection
```

## Roadmap

- Rust + Ratatui rewrite (vault format & API contract stay stable)
