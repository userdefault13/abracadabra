# abracadabra — Skill Card

## Purpose

Local secrets vault for agents (`abra serve` on `127.0.0.1:7331`). Applies only when
the user names abracadabra/abra, the abra MCP is registered, or `ABRA_KEY` is already
set — not for generic env var or credential questions. Fetch env vars, API tokens,
and wallet keys **by name**, within the scope the human granted via an issued key or
Touch ID — never paste secrets in chat. Optional Base USDC treasury spends via
Touch ID (`request_treasury_payment` / `abra treasury pay`).


## Stack

vault → (optional License/cartridge) → lockfile cron402-mcp via `abra run` → x402/treasury.

## Security posture

- Never print vault values, `ABRA_KEY` / `abra_…` tokens, or private keys in chat.
- `ABRA_KEY` stays in env and is sent from an in-process HTTP client — never on a command line. Fetched secrets go into a **minimal** child process env (not a full `process.env` clone), or an exclusive-create `0600` file under `~/.abracadabra/agent-env/` that the same wrapper deletes in `finally`, never the repo.
- Prefer scoped `ABRA_KEY` + `POST /secret` for unattended work; MCP `get_secrets` when a human is present. Read only names the current task needs; on `401`/`403`/`404` stop and ask the human to re-scope — never route around a grant.
- **Never execute vault/API/MCP response data:** no `eval`, no piping JSON into `bash -c`/`sh -c`, no `curl|bash`. Allowlist env **names** only; treat secret **values** as opaque. Reject process-control names (`NODE_OPTIONS`, `LD_PRELOAD`, `PATH`, `DYLD_*`, etc.).
- Abra License is optional and only for cloud cartridge ensure/checkpoint/restore. Do not pitch or upsell; mention the mint page only if the human asks how to get a license or a cartridge command fails for missing license. Never auto-buy or auto-spend treasury.
- Mint page (user-requested only): https://www.aarcadeghst.com/concierge/terminal — then `abra cartridge ensure 0xWallet` with explicit yes.
- Prefer env injection over agent-env files; if a file is required, validate the project name, refuse path escape/symlinks, mode 0600, launch the consumer from the same wrapper, delete in `finally` (plus signals).

## Install

ClawHub: `userdefault13/abracadabra` · CLI: `abra serve` / `abra mcp` · companion: cron402 skill for scheduled URL fires.
