# Cross-platform support (Linux & Windows)

**Status:** draft · **Owner:** abracadabra  
**Goal:** ship Tier 1 (keystore + password gate) without breaking macOS behavior or the vault/API contract.

Today abracadabra is **macOS-only** by design: Touch ID via a Swift helper and the vault master key in **Keychain** (`security` CLI). Everything else — encrypted vault file, loopback API, API keys, MCP, USB passphrase bundles — is already portable in principle.

This doc defines platform abstractions, a phased rollout, and a Tier 1 task list so GotchiBot Solo (and other consumers) can use `abra run …` on Linux and Windows without waiting for the full Rust rewrite.

---

## Goals

| In scope | Out of scope (for now) |
|----------|-------------------------|
| Linux x64/arm64 CLI: `set`, `get`, `run`, `serve`, `mcp`, `keys` | Mobile (iOS/Android) |
| Windows x64 CLI (native; WSL is a nice-to-have test target) | Unencrypted cloud-hosted vault |
| Same vault file format (`abracadabra-vault` v1) on all OSes | Changing USB bundle format |
| Same loopback API (`127.0.0.1:7331`, `POST /secret`); optional `serve --lan` | Biometric parity on day one |
| USB backup/restore/sync across Mac ↔ Linux ↔ Windows | TUI parity (Ink works; polish later) |
| Volume discovery: macOS `/Volumes`, Linux media paths, Windows drive letters | Mesh / multi-peer LAN sync |

**Compatibility promise:** a vault created on macOS must open on Linux/Windows after USB restore (or copy `vault.enc` + re-wrap master key on the new machine). API keys and project structure are unchanged.

---

## Current architecture (macOS coupling)

```
┌─────────────────────────────────────────────────────────────┐
│  CLI / API / MCP (TypeScript, platform-agnostic)            │
│  vault.ts · apikeys.ts · backup.ts · connectors · mcp     │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌─────────────────────┐           ┌─────────────────────┐
│ PlatformKeystore    │           │ PlatformAuth        │
│ src/core/keychain.ts│           │ src/auth/touchid.ts │
│ `security` CLI      │           │ vendor/auth-helper  │
│ Keychain            │           │ Swift LAContext     │
└─────────────────────┘           └─────────────────────┘
```

| File | macOS today | Blocks Linux/Windows |
|------|-------------|----------------------|
| `src/core/keychain.ts` | `security find-generic-password` / `add-generic-password` | **Yes** — no `security` on other OSes |
| `src/auth/touchid.ts` | compiles `auth-helper.swift` with `swiftc` | **Yes** — Swift/LAContext is Darwin-only |
| `scripts/postinstall.js` | runs `npm run setup` (swiftc) on `darwin` only | Warn-only on other platforms |
| `src/core/vault.ts` | AES-256-GCM, `~/.abracadabra/vault.enc` | **No** — portable |
| `src/core/backup.ts` | scrypt + AES bundle with vault + master key | **No** — portable |
| Web dash passkeys | `@simplewebauthn/server` | Partial — server still calls `authenticate()` for sensitive actions |

`ABRA_SKIP_BIOMETRICS=1` skips Touch ID prompts but **does not** replace Keychain; the CLI still fails on Linux/Windows at `getMasterKey()`.

---

## Platform abstraction

Introduce two small interfaces. Tier 1 implements them in TypeScript; the Rust rewrite should preserve the same contracts.

### `PlatformKeystore`

Responsible for the **32-byte vault master key** only (not per-var secrets — those live inside `vault.enc`).

```ts
// src/platform/keystore.ts (proposed)

export interface PlatformKeystore {
  /** Stable id for logs/doctor, e.g. "macos-keychain", "linux-secret-service". */
  readonly id: string;

  /** Load existing key or create + persist a new one (first run). */
  getOrCreateMasterKey(): Promise<Buffer>;

  /** Overwrite key (USB restore, key rotation). Must verify readback. */
  storeMasterKey(key: Buffer): Promise<void>;

  /** Optional: delete key (factory reset). */
  deleteMasterKey?(): Promise<void>;
}
```

**Selection order (proposal):**

| OS | Primary backend | Fallback |
|----|-----------------|----------|
| macOS | Keychain via `security` (current) | — |
| Linux | [libsecret](https://wiki.gnome.org/Projects/Libsecret) via `secret-tool` or `keytar` | Passphrase-wrapped key file in `~/.abracadabra/master.key.enc` (unlock at `abra unlock`) |
| Windows | Credential Manager via `keytar` or DPAPI | Same passphrase file fallback |

### Passphrase-file keystore (`ABRA_KEYSTORE=passphrase-file`)

Used for headless/SSH Linux when no OS credential store is available.

| Topic | Behavior |
|-------|----------|
| Wrap format | **v2**: scrypt `N=2^17` (131072), `r=8`, `p=1`, AES-256-GCM with AAD binding `{format,version,kdf}`. v1 files (`N=2^14`, no AAD) still open; successful unlock with a ≥12-char passphrase re-wraps to v2 atomically. |
| Passphrase minimum | **12 Unicode code points** (after NFKC) at creation / passphrase change. Existing shorter secrets still unlock (v1 stays until changed; USB restore of a short bundle passphrase is allowed with a stderr warning). |
| Prompt | Passphrase is read from the controlling terminal (`/dev/tty`) with echo off — not from stdin pipes, env, or argv. Use `ssh -t` over SSH. `ABRA_HEADLESS_PASSPHRASE` is CI-only (`ABRA_SKIP_BIOMETRICS=1` or `ABRA_AUTH=none`). |
| Session | `abra unlock` caches the **master key** in memory (TTL); the plaintext passphrase is **not** cached. Reboot / new process → locked. With **abra-agent** running, `abra unlock` also pushes the key into the agent so subsequent CLI processes need no prompt for vault I/O (see [abra-agent with passphrase-file](#abra-agent-with-passphrase-file) below). |
| Unlock backoff | After 5 consecutive wrong passphrases, exponential delay before the next try (`2^(failures-5)` seconds, cap 15 minutes). Never a hard lockout; counter in `unlock-attempts.json` (speed bump only — scrypt is the real cost). |

#### Migrating keytar → passphrase-file

Use when you need headless Linux (SSH / systemd) with `passphrase-file` + the
`passphrase` approval backend, but the master key still lives in keytar (Secret
Service / Credential Vault). On Linux, once `master.key.enc` exists it is
**auto-detected** (no required `ABRA_KEYSTORE` export). Full SSH walkthrough:
[LINUX-HEADLESS.md](./LINUX-HEADLESS.md).

```sh
# Prefer a backup first
abra usb backup

# Over SSH (PolKit cannot approve seatless sessions — one-time password auth):
ssh -t <host> 'ABRA_AUTH=password abra keystore migrate --to passphrase-file'
# Do not persist ABRA_AUTH=password in systemd units or shell rc.

# Or from a graphical session where PolKit / the keyring work:
abra keystore migrate --to passphrase-file
```

- The master key bytes do **not** change — only the wrap moves into `master.key.enc` (v2). `vault.enc` is untouched.
- **Keep-by-default:** without `--remove-old`, the keytar copy stays. While it exists, any same-user process with an unlocked keyring can still read the key. Remove later with `abra keystore migrate --to passphrase-file --remove-old` (types `delete` on `/dev/tty` after verify).
- Then: `abra doctor` (optional explicit `export ABRA_KEYSTORE=passphrase-file` / unit `Environment=`). If `ABRA_DIR` is customized, set the same value in the agent unit and shell.

macOS keychain → passphrase-file is not supported yet.

Use one npm dependency where possible:

- [`keytar`](https://github.com/atom/node-keytar) — Keychain / Secret Service / Credential Vault (native addon; needs prebuilds for CI).

Alternatively, a thin Rust `abracadabra-keystore` crate (aligned with roadmap) with Node N-API bindings.

### `PlatformAuth`

Responsible for **human approval** before returning secrets (API `POST /secret`, `abra get`, MCP `get_secrets`, issuing API keys, etc.).

```ts
// src/platform/auth.ts (proposed)

export interface AuthRequest {
  /** Shown in the system prompt, e.g. "curl (pid 81318) requests CLOUDFLARE_API_TOKEN from myproj". */
  reason: string;
  timeoutSeconds?: number;
}

export interface PlatformAuth {
  readonly id: string;

  /** Resolve when user approves; reject on deny/timeout. */
  authenticate(req: AuthRequest): Promise<void>;

  /** True if this backend can show OS-native biometrics. */
  supportsBiometrics(): boolean;
}
```

**Selection order (proposal):**

| OS | Tier 1 | Tier 2 |
|----|--------|--------|
| macOS | Touch ID / passcode (`auth-helper`) | unchanged |
| Linux | Password prompt on stdin (hidden) or `ABRA_SKIP_BIOMETRICS=1` + warn | polkit / fprint / KDE Wallet prompt |
| Windows | Console password prompt or CredUI | Windows Hello |

**Existing escape hatches (keep):**

- `ABRA_SKIP_BIOMETRICS=1` — skip `authenticate()` entirely (dev/CI only; document risk).
- API keys (`abra keys new`) — scoped bearer tokens, no per-request auth (unchanged).
- Session grants (`ttl` on `POST /secret`) — unchanged.

### Factory

```ts
// src/platform/index.ts (proposed)

export function createKeystore(): PlatformKeystore;
export function createAuth(): PlatformAuth;

// Overrides for tests / headless CI:
// ABRA_KEYSTORE=passphrase-file | keychain | keytar | ...
// ABRA_AUTH=none | password | touchid | windows-hello | ...
```

Wire `vault.ts` to call `createKeystore()` instead of importing `getMasterKey` from `keychain.ts` directly. Wire `api/server.ts`, `commands/crud.ts`, and MCP to call `createAuth()` instead of `authenticate` from `touchid.ts`.

---

## Tiers

### Tier 1 — Ship Linux & Windows (no biometrics)

**User-visible behavior:** same CLI; unlock uses OS credential store or a one-time `abra unlock` passphrase per session; sensitive reads prompt for **account password** (not Touch ID).

| Area | Work |
|------|------|
| Keystore | `keytar` backend + passphrase-file fallback |
| Auth | Password prompt backend; honor `ABRA_SKIP_BIOMETRICS` |
| Install | Remove macOS-only failure modes; `postinstall` builds native addon, not `swiftc` |
| Doctor | `abra doctor` (new) prints platform, keystore id, auth id, vault path |
| Docs | README platform matrix; link this doc |
| CI | GitHub Actions: `ubuntu-latest`, `windows-latest` — unit tests + `ABRA_SKIP_BIOMETRICS=1` integration |

**Exit criteria:**

```bash
# Linux
abra project new gotchibot
abra set gotchibot OPENCODE_API_KEY
abra run gotchibot -- node -e "console.log(!!process.env.OPENCODE_API_KEY)"
abra serve   # POST /secret with API key works

# Windows (PowerShell)
abra run gotchibot -- node -e "console.log(!!process.env.OPENCODE_API_KEY)"
```

Vault round-trip: create on Linux → `abra usb backup` → restore on macOS (and reverse).

### Tier 2 — Native biometrics

| OS | Backend |
|----|---------|
| Windows | Windows Hello (WebAuthn or `UserConsentVerifier`) |
| Linux | fprintd / polkit where available; else Tier 1 password |

Dash: allow passkey-only unlock on non-macOS without server-side Touch ID for read-only views; keep auth gate for reveal/copy/issue.

### Tier 3 — Rust rewrite + parity

- Implement `PlatformKeystore` / `PlatformAuth` in Rust (`ratatui` TUI).
- Node CLI becomes thin wrapper or separate `abra` binary.
- Vault format and HTTP API remain stable (version bump only if unavoidable).

---

## Tier 1 task list

Checkboxes are implementation order within abracadabra.

### A. Platform module

- [x] **A1** Add `src/platform/keystore.ts` — interface + macOS adapter (move logic from `keychain.ts`).
- [x] **A2** Add `src/platform/auth.ts` — interface + macOS adapter (wrap `touchid.ts`).
- [x] **A3** Add `src/platform/index.ts` — `process.platform` dispatch + env overrides.
- [x] **A4** Update `vault.ts` to use `createKeystore()` only (no direct `keychain` import).
- [x] **A5** Update all `authenticate()` call sites to use `createAuth()`.

### B. Linux keystore

- [x] **B1** Add `keytar` dependency; document build deps (`libsecret-1-dev` on Debian/Ubuntu).
- [x] **B2** Implement `KeytarKeystore` — service name `abracadabra-master-key`, account = username.
- [x] **B3** Implement `PassphraseFileKeystore` fallback — `~/.abracadabra/master.key.enc` (scrypt + AES-GCM, same KDF params as USB bundle).
- [x] **B4** `abra unlock` / `abra lock` — session cache of master key in memory (optional TTL); required when using passphrase fallback.

### C. Windows keystore

- [x] **C1** Verify `keytar` prebuild on `windows-latest` CI.
- [x] **C2** Same service/account naming as Linux.
- [x] **C3** Passphrase fallback + `abra unlock` (shared with B4).

### D. Auth (Tier 1)

- [x] **D1** `PasswordPromptAuth` — read password from stdin (no echo); used on linux/win32.
- [x] **D2** `NoAuth` — when `ABRA_SKIP_BIOMETRICS=1`; log one-line warning on startup.
- [x] **D3** Ensure `enqueueAuth()` in API server still serializes prompts.

### E. Packaging & DX

- [x] **E1** Replace `scripts/ensure-macos.js` with `scripts/ensure-platform.js` — warn + doctor hints per OS.
- [x] **E2** `postinstall`: on linux/win, run `keytar` rebuild or document `npm rebuild keytar`.
- [x] **E3** Add `abra doctor` — platform, keystore, auth, vault exists, `serve` health, API key count.
- [x] **E4** README: platform table; remove "macOS only" after Tier 1 ships.

### F. Tests & CI

- [x] **F1** Unit tests with injectable fake keystore/auth (no OS deps).
- [x] **F2** Workflow `.github/workflows/cross-platform.yml` — `npm test` on ubuntu + windows + macos with `ABRA_SKIP_BIOMETRICS=1`.
- [x] **F3** Smoke script: create project → set → run → export env (headless). (`npm run smoke` — `scripts/smoke-headless.mjs`, CI `cross-platform.yml`)

### G. USB / migration

- [x] **G1** Document: moving Mac vault to Linux = `abra usb restore` or copy bundle (master key re-wrapped into new keystore on restore — **already** what restore does). See [Linux / Windows onboarding](../../GotchiBot/docs/SOLO-LINUX-WINDOWS.md) and `abra usb restore` below.
- [x] **G2** On restore to new OS, call `storeMasterKey()` on the local `PlatformKeystore` after decrypting bundle (verify existing `usb restore` path). `restoreMasterKey()` handles passphrase-file; smoke + `src/platform/restore.test.ts` on Linux CI.

---

## Security notes

1. **Passphrase fallback** is weaker than OS keychain (file on disk). Restrict to `0600`, warn in doctor, prefer keytar when Secret Service / Credential Vault is available.
2. **`abra run` still does not prompt** — trusts the local user session (unchanged). Agents should use API keys or MCP on all platforms.
3. **Loopback-only API** — unchanged; no binding to `0.0.0.0`.
4. **API keys** — still hashed in vault; issuing/revoking requires `PlatformAuth` (password on Tier 1).
5. Parity with macOS Keychain caveat: document that any process running as the user can attempt keystore access; the auth gate is the primary control for interactive reads.

---

## Consumer impact (GotchiBot)

After Tier 1, friends on Linux/Windows can:

```bash
npm install -g @userdefault/abracadabra @userdefault/gotchibot
abra project new gotchibot
./scripts/gotchibot onboard          # saves GOTCHIBOT_INFRA_TOKEN via abra set
abra set gotchibot OPENCODE_API_KEY
abra run gotchibot -- ./scripts/gotchibot doctor
abra run gotchibot -- ./scripts/gotchibot tmux
```

GotchiBot changes (separate repo, optional until Tier 1 lands):

- Doctor: abra optional on non-macOS only after Tier 1; until then document env fallback.
- Remove hardcoded `/Users/…` paths; `CAST_BIN` from PATH.

---

## Open questions

1. **keytar vs Rust keystore** — ship keytar in Tier 1 for speed, or wait for Rust rewrite?
2. **Session `abra unlock`** — default TTL (e.g. 8h) vs unlock per `abra run`?
3. **WSL** — treat as Linux (Secret Service often missing); recommend passphrase fallback or 1Password bridge?
4. **Headless servers** — recommend API keys only + `ABRA_SKIP_BIOMETRICS=1` for `serve`?
5. **License NFT / activation** — same on all platforms, or macOS-only until Tier 2?

---

## References (current code)

| Concern | Location |
|---------|----------|
| Platform factory | `src/platform/index.ts` |
| Keystore interface | `src/platform/types.ts` |
| Master key (macOS) | `src/platform/keystore-macos.ts` (was `src/core/keychain.ts`) |
| Biometrics (macOS) | `src/platform/auth-macos.ts` (was `src/auth/touchid.ts`) |
| Skip auth (CI) | `src/platform/auth-none.ts` |
| Vault encrypt/decrypt | `src/core/vault.ts` |
| USB bundle | `src/core/backup.ts` |
| API + auth queue | `src/api/server.ts` |
| postinstall | `scripts/postinstall.js` |

---

## Changelog

| Date | Note |
|------|------|
| 2026-09-01 | Initial draft (Tier 1–3, trait boundaries, task list) |
| 2026-09-01 | A1–A5 landed: `src/platform/*`, vault + call sites wired |
| 2026-09-01 | Tier 1 B–E (except README + CI): keytar, passphrase-file, password auth, unlock/lock, doctor |
| 2026-09-25 | Linux PolKit per-reveal gate (`auth-polkit`, policy + `install-polkit.sh`); password prompt → stderr |
| 2026-09-25 | Passphrase-file H1: v2 wrap (scrypt 2^17 + AAD), tty-only prompt, no cached passphrase, unlock backoff |
| 2026-09-25 | H2: headless passphrase auth backend + headless-aware Linux auth selection (no password auto-select) |
| 2026-09-25 | Linux abra-agent (unix socket, idle lock, vault.load/save); systemd --user unit |

---

## Linux: PolKit approval gate

On Linux, interactive secret reveals (CLI `get`, MCP `get_secrets`, Cloudflare mint, etc.) go through `authenticate()` → `PlatformAuth`. The default backend on Linux is **always `polkit`** (per-reveal system prompt, similar to 1Password on Linux / Touch ID on macOS). If `pkcheck` or the policy file is missing, every reveal is **denied** with an actionable error pointing at `sudo scripts/install-polkit.sh` — there is no automatic fallback to the password prompt.

### Install the policy

```bash
sudo scripts/install-polkit.sh
# installs packaging/linux/dev.abracadabra.policy →
#   /usr/share/polkit-1/actions/dev.abracadabra.policy
```

Verify:

```bash
pkaction --action-id dev.abracadabra.reveal --verbose
```

Requires `pkcheck` (usually `/usr/bin/pkcheck` from the `polkit` package).

### Selection and overrides

| Condition | Auth backend |
|-----------|--------------|
| `ABRA_AUTH` set | that value (`polkit` / `passphrase` / `password` / `none` / …) |
| `ABRA_SKIP_BIOMETRICS=1` | `none` |
| macOS | `macos-touchid` |
| Linux, headless + `ABRA_KEYSTORE=passphrase-file` | `passphrase` (tty vault-passphrase prompt) |
| Linux, headless + other keystore | `polkit` (denies immediately — no dialog) |
| Linux, graphical | `polkit` |
| Windows / other | `password` |

`ABRA_AUTH=password` on Linux is an **explicit, less-safe opt-in** (press-Enter confirm, no identity check); it is **never** selected automatically. `abra doctor` flags a missing policy as a failure when auth is `polkit`. `ABRA_AUTH=polkit` on non-Linux is rejected. Policy defaults use **`auth_self`** (not `auth_self_keep`) — every reveal prompts; nothing is cached.

### Headless Linux (SSH / no desktop)

**Detection** (`detectHeadlessSession`, Linux only): headless when `SSH_CONNECTION` or `SSH_TTY` is non-empty, **or** when neither `WAYLAND_DISPLAY` nor `DISPLAY` is set and `XDG_SESSION_TYPE` is not `wayland`/`x11`. Non-Linux reports `headless: false` with a “not linux” reason.

**Auth selection (auto, no `ABRA_AUTH`):**

| Session | Keystore | Auth |
|---------|----------|------|
| Headless | `passphrase-file` | `passphrase` |
| Headless | `keytar` (default) / other | `polkit` → **denied** (no dialog); set `ABRA_KEYSTORE=passphrase-file` (run: `abra keystore migrate --to passphrase-file`) |
| Graphical | any | `polkit` |

**Passphrase approval (`ABRA_AUTH=passphrase` or auto headless + passphrase-file):**

- Requires a controlling terminal — use `ssh -t`. Without a TTY: denied with an `ssh -t` / `abra grant` hint.
- **Every** reveal prompts for the vault passphrase (no grace window, no caching). Wrong guesses count toward unlock backoff (same counter as `abra unlock`).
- On success, a locked passphrase-file session is unlocked (same effect as `abra unlock`) so the reveal can proceed; the next reveal still prompts.
- MCP / HTTP API while headless cannot complete passphrase approval without a TTY — pre-approve with [`abra grant`](#abra-grant-headless-mcpapi) (caller-bound, agent-held), or use a scoped API key (`abra keys new`) for LAN/non-interactive.
- `ABRA_AUTH=password` is never auto-selected on Linux.

### abra grant (headless MCP/API)

With `ABRA_AUTH=passphrase`, every reveal needs a TTY. MCP over stdio and the loopback API have none, so they are denied unless the user pre-approves a **specific caller binary** on a terminal:

```bash
abra unlock                                          # agent must hold the key
abra grant --project myproj --caller /path/to/client --ttl 2h
# then headless MCP/API reveals for that exact binary + project succeed until expiry/lock
abra grant --list
abra grant --revoke <id>   # or --revoke all
```

**Flow**

1. On a terminal: `abra grant --project <P> --caller <exe> --ttl <≤8h>` prompts for the vault passphrase (per-reveal approval), then asks the unlocked agent to store a grant in memory.
2. Headless MCP `get_secrets` / loopback `POST /secret`: passphrase auth fails with no-TTY → resolve real caller identity → `grant.check` on the agent → allow if exact match.
3. Grants never extend the agent's idle / max-age timers. They are **cleared** on every lock: `abra lock`, idle, max age (8h), sleep, and agent stop.

**Caller identity (never `requestedBy`)**

| Path | Identity |
|------|----------|
| MCP | Parent of `abra mcp` (`process.ppid`) — the MCP client that spawned it |
| Loopback API | Peer PID from `lsof` on the client port, then `/proc/<pid>/exe` |
| Matching | `realpath(exe)` + `stat` device + inode — exact match on project + exe + dev + ino |

Self-reported `requestedBy` / API `appId` may still appear in approval messages but are **never** used for grant matching.

**Interpreter caveat:** An MCP client that is a Node/Python script shows up as `node` / `python3`. Granting an interpreter covers **any** script it runs — refused unless `--allow-interpreter`. Prefer a dedicated binary when possible. If a wrapper shell launches `abra mcp`, the parent is the shell (grant that shell only with `--allow-interpreter`, which is broad).

**Out of scope:** Payments / signing / keygen / connect / API-key issuance / cartridge / LAN sync / passkeys keep calling `authenticate()` directly and stay **denied** headless even when a matching grant exists.

**TTL session grants disabled:** Under the passphrase backend, the existing MCP/API `ttl` “session grants” (keyed by self-reported `requestedBy` / `appId`) are neither consulted nor issued — that would reintroduce a grace window. Other auth backends are unchanged.

### MCP / headless

MCP tools already call `authenticate()` (or `authorizeReveal` for `get_secrets`); no MCP-specific PolKit path. A **graphical polkit agent** must be running in the active session (GNOME, KDE, wlroots portals, etc.). Headless SSH without `passphrase-file` is denied by PolKit auth; with `passphrase-file`, approvals prompt on the terminal (`ssh -t`) or use `abra grant` for MCP/API reveals.

The opt-in password prompt (`ABRA_AUTH=password`) writes only to **stderr** so it never corrupts MCP JSON-RPC on stdout — but without a TTY it still denies (same as before). Prefer PolKit, passphrase-file + tty / `abra grant`, or a scoped API key for agents.

### Omarchy / Quickshell

On Omarchy, the polkit agent runs inside the Quickshell shell. Machines without a fingerprint reader (e.g. 2020 iMac) show a **password** dialog from that agent — still one prompt per reveal.

### Optional: FIDO2 / pam-u2f (Touch-ID-like tap)

Optional. You can configure **pam-u2f** so the polkit-1 PAM stack accepts a security key tap. This changes PAM for `polkit-1`; keep a password fallback and test from a second session before relying on it. Not required for abracadabra.

---

## Linux: abra-agent (per-user key-holding agent)

> **Headless / SSH / systemd --user:** see [LINUX-HEADLESS.md](./LINUX-HEADLESS.md)
> (unit hardening without user namespaces, keystore auto-detect, migrate over SSH,
> `abra agent status --wait`).

Modelled on 1Password’s Linux design: a **background user agent** holds the unlocked vault master key in memory and **actually locks** (idle + absolute max age + sleep + explicit), so `abra` commands stop each reading a login-unlocked Secret Service / keyring entry — or, with passphrase-file, stop each re-prompting.

### Overview

| Piece | Detail |
|-------|--------|
| Socket | `$XDG_RUNTIME_DIR/abra/agent.sock`, or `/run/user/<uid>/abra/agent.sock` when `XDG_RUNTIME_DIR` is unset and `/run/user/<uid>` is a `0700` dir owned by you (override: `ABRA_AGENT_SOCKET`) |
| Dir perms | Runtime dir `0700`, owner must be the agent uid; refuse group/other bits and symlinks |
| Socket perms | `0600` after listen |
| Protocol | Newline-delimited JSON (`status`, `unlock`, `unlock.key`, `lock`, `vault.load`, `vault.save`, `grant.add` / `grant.list` / `grant.revoke` / `grant.check`) — **never** sends the master key to clients. `unlock.key` is the only path that carries key material, and only **CLI → agent**. Grants are metadata only (exe path + inode + project + expiry). |
| Peer check | Sensitive ops (`unlock`, `unlock.key`, `vault.load`, `vault.save`, `grant.*`) require the connecting peer to be the **abra CLI** (same `node` realpath + `dist/index.js` as argv[1], no inject/debug flags in argv or `NODE_OPTIONS`). Relative argv[1] is resolved against the peer's `/proc/<pid>/cwd` before realpath. Resolved on Linux via socket inode + `ss -xpn` + `/proc/<pid>/{exe,cwd,cmdline,environ}`. Ambiguity / missing `ss` / non-Linux → `forbidden_peer` (fail closed). `status` / `lock` stay allowed for any same-uid peer (no secrets returned; lock only reduces access). |
| Vault binding | `vault.load` / `vault.save` / `unlock.key` include the client's resolved `vaultPath` + `keystoreBackend`; agent refuses (`mismatch`) if they differ from its own — client falls back to direct I/O |
| Idle lock | Default **15 min** (`ABRA_AGENT_IDLE_SECONDS`); activity = vault ops |
| Max age | Absolute **8 h** ceiling (`ABRA_AGENT_MAX_AGE_SECONDS`, values > 8h clamped); activity never extends it |
| Sleep lock | Linux: subprocess watches logind `PrepareForSleep(true)` via `/usr/bin/gdbus` (preferred) or `/usr/bin/dbus-monitor`; locks the agent. Best-effort (no logind inhibitor). Graceful no-op if binaries missing |
| Crypto | Agent encrypts/decrypts `vault.enc` with the same AES-256-GCM helpers as `core/vault.ts` |
| Fresh process | Always starts **locked**; no key file on disk for agent state — after reboot everything stays locked until `abra unlock` |

**Enabled by default** only on Linux when `XDG_RUNTIME_DIR` is set **or** a validated `/run/user/<uid>` fallback resolves (real directory, not a symlink, owned by you, mode `0700`). Elsewhere opt-in with `ABRA_AGENT=1` (+ socket path). `ABRA_AGENT=0` disables. macOS default behavior is unchanged (no agent). **Windows is unsupported** — `isAgentEnabled()` always returns false on win32 (even with `ABRA_AGENT=1`). **Sensitive agent ops are Linux-only** (no `/proc` / `ss` peer check elsewhere); on macOS with `ABRA_AGENT=1`, unlock/vault I/O return `forbidden_peer` and the client falls back to the direct keystore. Non-interactive SSH (e.g. Tailscale) often omits `XDG_RUNTIME_DIR` — see [LINUX-HEADLESS.md](./LINUX-HEADLESS.md#tailscale-ssh--non-interactive-ssh).

If the socket is missing, connect times out (~500ms), unlock fails (keyring locked / `VaultLockedError`), the peer is rejected (`forbidden_peer`), the agent returns `unavailable` / `mismatch` / `locked` (passphrase-file agent waiting for `abra unlock`), `loadVault` / `saveVault` **fall back** to the direct `resolveMasterKey(getKeystore())` path. The agent never mints a master key on unlock failure.

### Unlock vs reveal approval

Agent **unlock** is a keystore read (keytar) or a CLI-pushed key (passphrase-file) into agent memory. It does **not** satisfy PolKit / `authenticate()` reveal gates. CLI/MCP still call `authenticate()` before revealing secrets — under `ABRA_AUTH=passphrase` that means a **per-reveal** passphrase prompt even while the agent holds the key.

Sensitive socket ops are limited to the abra CLI peer (see Peer check above). That blocks casual same-uid dumpers (e.g. a compromised npm `postinstall`) without a PolKit prompt. It is **not** a full same-user security boundary. Residual risks if an attacker already runs as your uid:

- `kernel.yama.ptrace_scope=0` → ptrace / debugger attach to the agent or CLI
- reading `/proc/<pid>/mem` when permitted
- `LD_PRELOAD` / compromised `node` binary shared with the agent
- rewriting abracadabra’s installed files (`dist/index.js`) so a “valid” CLI peer is malicious

Treat the agent as a convenience lock for the login session, not as protection against a hostile same-uid process with full local privilege.

Raw-key callers (USB/LAN sync, cartridge checkpoint, keychain re-export) keep using `getMasterKey()` directly — there is no key-export op on the agent socket.

### abra-agent with passphrase-file

With `ABRA_KEYSTORE=passphrase-file`, each CLI process has its own in-memory session — `abra unlock` in one process does not help the next. The agent holds the key between commands.

**Flow:**

1. Start the agent (`systemctl --user start abra-agent` or `abra agent`). It starts **locked**.
2. On a terminal, run `abra unlock`. The CLI decrypts `master.key.enc` (tty `promptHidden`; with `ABRA_AUTH=passphrase` that single prompt is also the approval — otherwise authenticate first, then prompt).
3. If an agent socket is reachable, the CLI pushes the 32-byte key via `unlock.key` over the peer-checked socket (**CLI → agent only**; never agent → client). This is the one place key material crosses the socket.
4. Later `abra run` / vault ops use `vault.load` / `vault.save` with no passphrase prompt. Reveals still call `authenticate()` per reveal.
5. Locks: idle **15m**, absolute max **8h**, `abra lock`, logind sleep (`PrepareForSleep(true)`), and process exit / reboot (no persistence).

The bare `unlock` op (no key) on a passphrase-file agent returns `locked` with “run: abra unlock (on a terminal)” — it never calls the passphrase keystore (which could prompt). Clients treat that as unavailable and fall back to the direct path (`VaultLockedError`).

**Sleep watch subprocess:** Node has no native D-Bus addon in this tree. The agent spawns `/usr/bin/gdbus monitor …` (or `/usr/bin/dbus-monitor`) with no shell. The systemd unit already allows `AF_UNIX` (system bus). A logind inhibitor is **not** taken — lock is best-effort right before suspend. If neither binary exists, the agent logs once and continues without sleep lock.

### systemd --user

Full guide (hardening, peer check, SSH migrate, auto-detect):
[LINUX-HEADLESS.md](./LINUX-HEADLESS.md).

```bash
mkdir -p ~/.config/systemd/user
PKG="$(npm root -g)/@userdefault/abracadabra"
cp "$PKG/packaging/linux/abra-agent.service" ~/.config/systemd/user/
# Edit ExecStart to absolute node + absolute …/dist/agent/server.js
# (same node realpath + same package install as `abra` — peer check)
# Passphrase-file: optional Environment=ABRA_KEYSTORE=passphrase-file when
# master.key.enc exists (Linux auto-detect). Match ABRA_DIR if customized.
# Do not rely on mise/nvm PATH in the user manager.
systemctl --user daemon-reload
systemctl --user enable --now abra-agent
sudo loginctl enable-linger "$USER"   # optional: survive logout / no GUI seat
# Tailscale / non-interactive SSH often omits mise PATH; XDG_RUNTIME_DIR falls
# back to /run/user/<uid> when valid — see docs/LINUX-HEADLESS.md
ssh -t <host> 'PATH=$HOME/.local/share/mise/shims:$PATH abra unlock'
# or: ssh -t <host> ~/.local/bin/abra-unlock
```

Unit highlights (`packaging/linux/abra-agent.service`):

- `RuntimeDirectory=abra` + `RuntimeDirectoryMode=0700` — creates `$XDG_RUNTIME_DIR/abra`.
- **No** `PrivateTmp` / `ProtectSystem` / `ProtectHome` / `ReadWritePaths` in the
  user unit — those imply a user namespace and break peer PID resolution
  (`forbidden_peer` / `peer_pid_unresolved`). See [LINUX-HEADLESS.md](./LINUX-HEADLESS.md).
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` — D-Bus/agent socket + `ss` sock_diag.
- Sleep lock needs `/usr/bin/gdbus` (or dbus-monitor) executable; no `SystemCallFilter` is set that would block that spawn.

CLI:

- `abra agent` — foreground agent (signal handlers; sleep watch on Linux)
- `abra agent status [--wait] [--timeout N] [--json]` — unlocked / locked / not running
- `abra unlock` — passphrase-file: unlock local session + push key to agent when reachable
- `abra lock` — clear local session and lock the agent when present (also clears agent-held grants)
- `abra grant` — pre-approve a caller binary for headless MCP/API reveals under the passphrase backend

See packaging unit comments and [LINUX-HEADLESS.md](./LINUX-HEADLESS.md) for hardening notes (`LimitCORE=0`, no `MemoryDenyWriteExecute`).
