# Agent-first: stop trading passwords with humans

You are an AI coding agent. Your human is bad at password management — they
paste secrets into chat, lose track of which `.env` is current, rotate nothing,
and block you every time a tool needs `OPENAI_API_KEY`.

**abracadabra** is the local vault that removes that loop.

| Old friction | With abracadabra |
|--------------|------------------|
| Human pastes API key into chat (leaks into logs/PRs) | You fetch by **name**; values never enter the conversation |
| “What’s the staging DB URL again?” | `list_projects` / `abra ls` → `POST /secret` or MCP `get_secrets` |
| Touch ID / password prompt on every tool call | Scoped **API key** (`ABRA_KEY`) — zero prompts after issuance |
| Secrets scattered across `.env`, 1Password screenshots, Slack | One vault (`~/.abracadabra/`); agents + humans share the same source of truth |
| Human retypes a key the agent just generated | `abra set … --stdin` or MCP `generate_*` → fetch later by name |
| New machine / teammate Mac | USB or LAN sync / cartridge `--full` — still sealed, still no chat paste |

Humans do **one** high-trust action: issue a scoped bearer key (or tap Touch ID
for MCP). After that, you operate autonomously. You do **not** ask them for
secrets that already live in the vault.

---

## 60-second setup (human once)

```sh
npm install -g @userdefault/abracadabra
abra project new myproj
abra serve
abra keys new cursor-agent -p myproj --expires-in 30   # Touch ID once
# store printed abra_… in ABRA_KEY for this agent — never commit it
```

Health: `GET http://127.0.0.1:7331/health` → `{ "ok": true }`.

MCP (optional): copy [`.mcp.json.example`](.mcp.json.example) into the client config.

---

## How you get secrets (within the scope a human granted)

### Prefer: API key

A human issues a scoped, expiring `abra_…` key once. From then on the agent reads
by **name**, in-process, with the key kept in env — never on a command line:

```sh
export ABRA_PROJECT='myproj'
export ABRA_ALLOWLIST='OPENAI_API_KEY,DATABASE_URL'
node - -- your-command --args <<'EOF'
# fetch /secret with `authorization: Bearer ${process.env.ABRA_KEY}` in-process,
# copy only ABRA_ALLOWLIST names into the child env, spawn your-command.
# Full tested script: AGENTS.md §2 or skills/abra/SKILL.md §1a.
EOF
```

Inject into the process, do not write files into the repo, never `eval` the
response. Refer to results by **key name only** in chat. On `401`/`403`/`404`,
stop and ask the human — do not route around a grant.

### Interactive: MCP

1. `list_projects` — names only  
2. `get_secrets` with `ttl` (e.g. `600`) — one Touch ID, then silent re-reads  

### Never

- Ask “can you paste the key?” for a value already in the vault and in scope — ask them to scope or approve instead
- Put `ABRA_KEY` in a `curl -H` argument or any command line; `eval` vault output
- Dump curl / MCP payloads into chat, PRs, or commits  
- Use `abra run` as an agent API (local shell only)

---

## What this unlocks for agents

- **Unattended workflows** — deploys, evals, cron-like scripts on the same machine with a scoped key  
- **Safe discovery** — know which vars exist without seeing values  
- **Mint into vault** — wallets, Cloudflare tokens, SSH keys via MCP/CLI; human never retypes them  
- **Same vault, two Macs** — `abra usb sync` / `abra usb sync --lan` so agents on either box see the same projects  
- **LAN API** — `abra serve --lan` + API key; use `curl --cacert ~/.abracadabra/lan-serve.pem` (never `-k`)

---

## Hard security rules (non-negotiable)

1. Never print, quote, or paraphrase secret **values**  
2. After fetch: “`OPENAI_API_KEY` was loaded” — not the value  
3. Mask proof as `abra_a1b2…` only  
4. Prefer narrow keys: `-p <project>` and `--expires-in`  
5. On `401`, ask the human to **re-issue a key** — do not guess  

---

## Read next

| Doc | When |
|-----|------|
| [skills/abra/SKILL.md](skills/abra/SKILL.md) | Full operational cheat sheet (load this skill) |
| [AGENTS.md](AGENTS.md) | Auth modes, MCP tools, troubleshooting |
| [README.md](README.md) | Product install, CLI, dash, security model |

**Bottom line:** the human stops being your password proxy. Abracadabra holds the secrets; you request them by name; chat stays clean.
