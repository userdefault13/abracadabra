# Remote unlock (hub-held unwrap key)

Status: **PR 1/7 in progress** — device key + pinned hub key outside the vault.
Feature flag: off by default (`ABRA_REMOTE_UNLOCK=1` to enable later listeners/CLI).
Nothing new runs unless you invoke it. Julius approved both phases; bot lease
default TTL is **7 days**.

Design source: [REMOTE-UNLOCK-DESIGN.md](./REMOTE-UNLOCK-DESIGN.md).

## What PR 1 ships

| Piece | Path | Notes |
|-------|------|--------|
| Device key | `<abraDir>/remote/device-key.json` | Ed25519 + X25519, 0600 in a 0700 dir |
| Hub pin | `<abraDir>/remote/hub-pin.json` | Hub `deviceId` + public keys only |
| Feature flag | `ABRA_REMOTE_UNLOCK` | Must be `1` for future unlock/listener paths |
| Hidden CLI | `abra remote whoami` | Prints **public fingerprint only** |

## Threat model (device key alone)

The device key lives outside the vault so a **locked** receiver can still sign
challenges and decrypt hub replies. Compromise of this file (disk theft, bad
perms) lets an attacker **ask** the hub to unlock — it does **not** unwrap the
local vault by itself. Unlock still needs:

1. A prior enroll that left a wrap blob on the receiver and wrap key `W` in the hub vault
2. Touch ID (or equivalent) approval on the hub
3. Verification against the pinned hub / device public keys

Stolen receiver disk without `W` → blob useless. Compromised unlocked hub + Touch ID →
same trust as today's sync push. Hub offline → local unlock unchanged.

POSIX load is fail-closed: group/world-readable files or wrong owner uid refuse
to load. win32 skips mode checks (existing platform pattern).

## PR plan (1–7)

1. **Device key + pinned hub key** (this PR) — agent dir, 0600, fail-closed perms; tests
2. **Enroll** — `abra remote enroll <peer>`: create `W`, blob, seal `W` to hub; Touch ID on hub
3. **Wire protocol** — challenge/response, signatures, nonce cache, 30s expiry, tailnet listener
4. **CLI** — `unlock|lock|status --all|--peers`, `revoke`, `disable`; audit log both sides
5. **Relock policy** — signed policy field, local caps
6. **(Phase 2) Lease store** — survives lock; serve path bound to `GrantCaller`
7. **(Phase 2) Hub renewer + revoke** — `abra lease grant … --ttl` (default 7d)

## Ops notes

```sh
# Optional: create/show device fingerprint (hidden; does not enable unlock)
abra remote whoami
```

Private keys are never printed, logged, or returned in errors. Prefer
`ABRA_DIR` overrides in tests; never commit `remote/*.json`.
