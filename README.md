# ✦ abracadabra

<a href="assets/logo.svg"><img src="assets/logo.svg" width="64" alt="abracadabra logo"></a>

Terminal vault for env vars & passwords, with a biometric-gated local API so
dapps and scripts can pull secrets on demand — and a subprocess wrapper that
injects them invisibly into any command.

**npm:** [`@userdefault/abracadabra`](https://www.npmjs.com/package/@userdefault/abracadabra) ·
**Source:** [github.com/userdefault13/abracadabra](https://github.com/userdefault13/abracadabra) (public) ·
**Site:** [aarcadeghst.com](https://www.aarcadeghst.com)

**macOS** (full) · **Linux / Windows** (Tier 1 — keytar or passphrase-file) · Node 20+ · loopback API on `127.0.0.1:7331`

| OS | Default keystore | Default auth | Notes |
|----|------------------|--------------|-------|
| macOS | Keychain | Touch ID | unchanged |
| Linux | keytar (Secret Service) | password prompt | `libsecret-1-dev` for builds; fallback: `ABRA_KEYSTORE=passphrase-file` |
| Windows | keytar (Credential Vault) | password prompt | fallback: `ABRA_KEYSTORE=passphrase-file` |

> Design + task list: [docs/CROSS-PLATFORM.md](docs/CROSS-PLATFORM.md).

```sh
npm install -g @userdefault/abracadabra   # compiles Touch ID helper on first install (Xcode CLT required)
abra project new myproj
abra serve                   # local API + web dash
```

See **[README.agents.md](README.agents.md)** (agent-first: cut human–password friction) and
**[AGENTS.md](AGENTS.md)** (API keys, MCP, session grants). Skill: [`skills/abra/SKILL.md`](skills/abra/SKILL.md).

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

## Trust & licensing

Source is **public** so you can inspect crypto, Touch ID gating, and API behavior before
trusting the vault with secrets. Licensed under [PolyForm Noncommercial 1.0.0](LICENSE) —
free for personal and noncommercial use.

| Entitlement | What it unlocks |
|---|---|
| **Abra License NFT** (Base) | Full product activation; sold via [AarcadeGh$t](https://www.aarcadeghst.com) |
| **Separate commercial agreement** | Paid hosting, white-label, or other commercial use of the code |

Details: [COMMERCIAL.md](COMMERCIAL.md). Trademarks (`abracadabra`, `AarcadeGh$t`) are not licensed.

## Setup

Requires **Node 20+**, **macOS** (Touch ID + Keychain), and **Xcode Command Line Tools** (for the Touch ID helper).

**From npm (recommended):**

```sh
npm install -g @userdefault/abracadabra
abra project new myproj    # first run creates ~/.abracadabra/
```

**From source:**

```sh
npm install
npm run build
npm run setup   # compiles the Touch ID helper (swiftc → vendor/auth-helper)
npm link        # installs `abra` on your PATH
```

## Updates

`abra` (TUI) and `abra serve` check for newer releases on launch (CDN → www API → GitHub → npm).
Skip with `ABRA_SKIP_UPDATE_CHECK=1`; force every launch with `ABRA_UPDATE_CHECK=always`.

```sh
abra update --check    # compare installed vs latest
abra update --apply    # npm install -g @userdefault/abracadabra@latest
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

## For AI agents

Start here: **[README.agents.md](README.agents.md)** — why abracadabra removes
human↔agent password friction, and how to fetch secrets without pasting keys into chat.

abracadabra is built for coding agents. Three integration paths:

| Path | Touch ID | Docs |
|------|----------|------|
| **API key** (`Authorization: Bearer abra_…`) | Once at issuance | [AGENTS.md](AGENTS.md#api-key-workflow-recommended-for-agents) |
| **Session grant** (`ttl` on `POST /secret`) | Once per app + project | [AGENTS.md](AGENTS.md#session-grants-http-multi-step-flows) |
| **MCP** (`abra mcp`) | Per read (or once with `ttl`) | [AGENTS.md](AGENTS.md#mcp-setup) |

```sh
abra keys new my-agent -p myproj     # human issues scoped key
abra serve                           # agent calls POST /secret with bearer token
```

Copy [`.mcp.json.example`](.mcp.json.example) into your agent client config for MCP access.
Agent skill file: [`skills/abra/SKILL.md`](skills/abra/SKILL.md).

> **`abra run` is not an agent API** — it injects secrets into a subprocess
> without per-run Touch ID (local dev convenience). Agents should use API keys
> or MCP instead.

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
| `abra serve [--port 7331] [--open] [--lan]` | Start the local biometric-gated API + web dash (`--lan` = TLS on all interfaces) |
| `abra keys new <name> [-p projs] [--expires-in d]` | Issue an API key for `POST /secret` (printed once) |
| `abra keys ls` / `keys rm <id>` | List (masked) / revoke API keys |
| `abra usb list [--lan]` | List mounted volumes (and optional LAN peers) |
| `abra usb backup [-v vol] [-f dir]` | Write a passphrase-encrypted bundle (vault + master key) to USB |
| `abra usb restore [target]` | Restore vault + master key from a bundle |
| `abra usb sync [-v vol] [--dry-run] [--theirs/--ours]` | Two-way 3-way-merge sync with the USB copy |
| `abra usb host [--port] [--ttl]` | Start a short-lived TLS LAN sync host (PIN + mDNS) |
| `abra usb peers` | Browse LAN for sync hosts |
| `abra usb sync --lan [host] [--pin] [--fingerprint]` | Sync with a LAN host |
| `abra cartridge checkpoint [--full]` | Cloud checkpoint (metadata, or sealed full vault with `--full`) |
| `abra cartridge restore` | Restore from latest full cartridge checkpoint |
| `abra update [--check\|--apply\|--force]` | Check or install updates from CDN / npm |

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

### API keys (Touch ID once, then never)

For AI agents and CI-style scripts that can't answer Touch ID prompts, issue a
scoped bearer token instead:

```sh
abra keys new opencode-agent -p ai-cron-site      # scoped to one project
abra keys new backup-bot --expires-in 30          # all projects, expires in 30d
abra keys ls                                      # prefixes + scope only (never full keys)
abra keys rm <id>                                 # revoke
```

```sh
curl -X POST http://127.0.0.1:7331/secret \
  -H "Authorization: Bearer abra_<id>_<secret>" \
  -H 'Content-Type: application/json' \
  -d '{"project": "ai-cron-site", "keys": ["CDP_API_KEY"]}'
```

A valid key serves values **without any biometric prompt**, but only for its
scoped projects. Keys live in the vault (so they USB-sync between machines),
only SHA-256 hashes are stored, and issuing/revoking requires Touch ID.
Manage them from the dash too: **API Keys** panel in the sidebar.

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

Supported providers: **cdp** (Coinbase Developer Platform) · **cloudflare** · **digitalocean** · **nvidia** (NIM / Nemotron) · **openrouter** · **vercel**

```sh
abra connect cdp                 # opens portal, stores creds encrypted (hidden input)
abra connect cloudflare          # CLOUDFLARE_API_TOKEN + ACCOUNT_ID
abra connect digitalocean        # DIGITALOCEAN_TOKEN (+ optional Spaces keys)
abra connect nvidia              # NVIDIA_API_KEY (Nemotron / NIM) (+ optional BASE_URL for self-hosted NIM)
abra connect openrouter          # OPENROUTER_API_KEY (+ optional BASE_URL)
abra connect vercel              # VERCEL_TOKEN (+ optional ORG_ID / PROJECT_ID)
abra connections                 # list connected accounts
abra issue cloudflare myproj     # Touch ID gate → provider vars into project
abra disconnect cloudflare
```

> **Nemotron note:** the key works with any OpenAI-compatible client pointed at
> `https://integrate.api.nvidia.com/v1` — e.g. `OPENAI_BASE_URL=$NVIDIA_BASE_URL`
> with `NVIDIA_API_KEY` as the bearer. Self-hosting NIM? Set a custom base URL
> when connecting and it gets issued alongside the key.

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
- **USB panel** — back up to a plugged-in drive and sync against its bundle
  (dry-run preview, conflict resolution) without leaving the browser
- **Biometric passkey gate (WebAuthn)** — the dash is covered by a full-page blur until
  you unlock with a passkey. First-time setup: click *Set up passkey* → approve the
  Touch ID prompt → save the passkey (Chrome can sync it to your Google Password
  Manager). Enrolling a passkey itself requires Touch ID on the server. Sessions last 12h.
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
abra keygen cloudflare myproj            # mint a FRESH Cloudflare token → CLOUDFLARE_API_TOKEN
abra keygen cloudflare myproj --expires-in 30 --perms "Workers Scripts Edit,KV Storage Edit"
abra keygen ssh myproj                   # ed25519 keypair → SSH_PRIVATE_KEY (secret) + SSH_PUBLIC_KEY
abra keygen ssh myproj -n 3              # multiple keys (_1 … _n suffixes)
```

Cloudflare minting uses the Account Owned Tokens API: the connected credential
must be an *Account Owned Token* with **API Tokens Write** (dash.cloudflare.com →
your account → Manage Account → Account API Tokens). Each project then gets its
own scoped, revocable token instead of sharing the admin one.

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
| `get_secrets` | `{ project, keys[], ttl?, requestedBy? }` | Touch ID gate → `{ approved: true, vars, grantedVia: "touch-id" \| "session-grant" }` |
| `list_grants` | — | Active MCP session grants for this `abra mcp` process |
| `generate_wallet` | `{ project, payTo?, chain? }` | Foundry wallet stored encrypted → `{ wallets: [{ address, varSuffix, payToSet }] }`; `chain: "base-sepolia"` adds chainId + USDC address + faucet hints for funding |
| `generate_cloudflare_token` | `{ project, perms?, expiresInDays?, requestedBy? }` | Touch ID gate → mints a fresh Account Owned token via the Cloudflare API, stored encrypted as `CLOUDFLARE_API_TOKEN` (value never returned to the agent — fetch via `get_secrets`) |
| `generate_ssh_key` | `{ project, count?, comment? }` | Local ed25519 keypair → `{ keys: [{ varSuffix, publicKey, comment }] }`; private key stored encrypted as `SSH_PRIVATE_KEY<varSuffix>` |

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

MCP session grants (`ttl` on `get_secrets`) are **in-memory for the `abra mcp`
process only** — separate from HTTP grants on `abra serve`.

## USB backup & sync between two computers

The vault alone is useless on another machine — its master key lives in *this*
Mac's Keychain. So a backup bundle (`.abrabak`) carries **both** the encrypted
vault **and** the master key, wrapped together under a passphrase you choose
(scrypt KDF → AES-256-GCM). Losing the stick is safe; losing the passphrase
means losing the backup.

```sh
abra usb list                  # mounted volumes + existing backups
abra usb backup                # → <volume>/abracadabra/backup-<ts>.abrabak
abra usb backup -v /Volumes/STICK
abra usb restore /Volumes/STICK   # or a specific file/dir; auto-detect if omitted
```

Backups are timestamped and never overwritten — `latest.json` points at the
newest one. Restoring replaces your local vault **and** Keychain master key
(double confirmation + Touch ID).

### Syncing two machines

Keep one USB stick as the meeting point:

```sh
# computer A
abra usb sync -v /Volumes/STICK        # first run: writes an initial backup

# computer B (same stick)
abra usb sync -v /Volumes/STICK        # pulls A's projects

# back on A, after editing on both sides
abra usb sync                          # 3-way merge against last-synced snapshot
abra usb sync --dry-run                # preview only
abra usb sync --theirs                 # force-resolve conflicts with the USB copy
```

Merge rules: additions/deletions propagate both ways; edits to the same var
resolve by newest `updatedAt`. True conflicts (same key edited on both sides,
or edited-vs-deleted) prompt per-key showing both values with timestamps.
`~/.abracadabra/sync-state.json` stores an **AES-256-GCM encrypted** snapshot of the
last synced vault (sealed with the same master key as `vault.enc`, mode `0600`)
so merges work offline without leaving plaintext secrets on disk.

### LAN sync (same merge, no stick)

One Mac hosts a short-lived TLS listener; the other joins with a PIN. mDNS
advertises the host as `_abracadabra-sync._tcp`.

```sh
# computer A
abra usb host                  # Touch ID → prints PIN, fingerprint, ip:port

# computer B
abra usb peers                 # optional: discover hosts
abra usb sync --lan            # pick a peer, enter PIN
abra usb sync --lan 192.168.1.20:7332 --pin 482910 --dry-run
abra usb sync --lan 192.168.1.20:7332 --pin 482910 --theirs
```

The transfer uses the same `BackupBundle` format sealed with the **PIN** (not
your USB passphrase). Confirm the TLS fingerprint when joining an untrusted
network. The host stops after a successful push or when `--ttl` expires
(default 10 minutes). The web dash USB panel can start/stop a host and join peers.

### `abra serve --lan`

```sh
abra serve --lan               # HTTPS on 0.0.0.0; writes ~/.abracadabra/lan-serve.pem
abra serve --lan --tls-cert c.pem --tls-key k.pem
```

Off-loopback `POST /secret` requires an API key (`Authorization: Bearer abra_…`).
Loopback behavior is unchanged. Prefer `--lan` only on trusted networks.

**TLS:** Clients must trust the printed CA file — e.g.
`curl --cacert ~/.abracadabra/lan-serve.pem …`. **Never use `curl -k` /
`--insecure`**; that disables MITM protection and can leak the bearer key and
secret payloads.

## Security model

- Vault is a single file at `~/.abracadabra/vault.enc`, AES-256-GCM encrypted;
  master key lives in the macOS Keychain (`abracadabra-master-key`)
- Vault writes are atomic (tmp + rename) with `0600` perms; directory is `0700`
- `sync-state.json` is encrypted with the same master key (legacy plaintext files are migrated on next sync)
- `abra get`, `abra env`, and unauthenticated `POST /secret` require per-use biometric approval
- API keys skip Touch ID on `POST /secret` but are scoped to specific projects
- **`abra run` does not require Touch ID** — it trusts the local shell user and
  injects secrets into the child process. Use API keys or MCP for agent access.
- `abra serve --lan` writes `lan-serve.pem` for `curl --cacert`; never use `curl -k`
- Cartridge `--full` requires a strong passphrase (≥16 chars, mixed classes) and slower scrypt
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

---

Logo/icon by [Flaticon](https://www.flaticon.com)

## Author

**Julius Wong** (userDef@ult) — [userdefault.dev](https://www.userdefault.dev) · [GitHub](https://github.com/userdefault13) · [X](https://x.com/userDefault_0x)

Freelance engineer working on AI agent orchestration, AI developer tooling, and Unity/WebGL
multiplayer games. Write-up of the AI tooling and credential-infrastructure work behind this project:
[userdefault.dev/work/abracadabra](https://www.userdefault.dev/work/abracadabra).

Available for freelance and contract work — [book a consult](https://www.userdefault.dev/hire),
or read more about [AI tooling & developer infrastructure](https://www.userdefault.dev/services/ai-tooling).
