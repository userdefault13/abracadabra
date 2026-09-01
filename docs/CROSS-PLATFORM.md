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
| Windows x64 CLI (native; WSL is a nice-to-have test target) | Cloud-hosted vault |
| Same vault file format (`abracadabra-vault` v1) on all OSes | Changing USB bundle format |
| Same loopback API (`127.0.0.1:7331`, `POST /secret`) | Biometric parity on day one |
| USB backup/restore/sync across Mac ↔ Linux ↔ Windows | TUI parity (Ink works; polish later) |

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
