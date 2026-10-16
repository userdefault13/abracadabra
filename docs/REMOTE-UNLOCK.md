# Remote unlock (hub-held unwrap key)

Status: **PR 2/7 in progress** — enroll (wrap blob + hub-held `unlockWrap`).
Feature flag: off by default (`ABRA_REMOTE_UNLOCK=1` to enable enroll / later listeners).
Nothing new runs unless you invoke it. Julius approved both phases; bot lease
default TTL is **7 days**.

Design source: [REMOTE-UNLOCK-DESIGN.md](./REMOTE-UNLOCK-DESIGN.md).

## What PR 1–2 ship

| Piece | Path | Notes |
|-------|------|--------|
| Device key | `<abraDir>/remote/device-key.json` | Ed25519 + X25519, 0600 in a 0700 dir |
| Hub pin | `<abraDir>/remote/hub-pin.json` | Hub `deviceId` + public keys only |
| Unlock blob | `<abraDir>/remote/remote-unlock.blob` | AES-256-GCM_W(masterKey); AAD = deviceId + master-key fingerprint |
| Hub wrap | `syncPeers[id].unlockWrap` | Device-local with peers; stripped on export; cleared on unpair |
| Feature flag | `ABRA_REMOTE_UNLOCK` | Must be `1` for enroll / future unlock listener |
| Hidden CLI | `abra remote whoami` | Prints **public fingerprint only** |
| Hidden CLI | `abra remote enroll <peer>` | Hub stores W (network transport → PR 3; loopback harness in tests) |

## Enroll (PR 2)

Receiver (local unlock): mint wrap key `W`, write `remote-unlock.blob`, seal `W`
to the hub's X25519 key, pin hub pubs, forget `W`.

Hub (Touch ID via existing auth path): only paired peers with role **receiver**
may enroll; store `W` under `syncPeers[id].unlockWrap`.

Re-enroll: if the receiver master key changes, the blob fingerprint check fails
→ clear error **"re-enroll needed"**.

Transport: pure `prepareReceiverEnroll` / `planHubEnroll` + in-process
`enrollLoopback`. Wire protocol / tailnet listener is PR 3.

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

1. **Device key + pinned hub key** — agent dir, 0600, fail-closed perms; tests
2. **Enroll** (this PR) — `abra remote enroll <peer>`: create `W`, blob, seal `W` to hub; Touch ID on hub
3. **Wire protocol** — challenge/response, signatures, nonce cache, 30s expiry, tailnet listener
4. **CLI** — `unlock|lock|status --all|--peers`, `revoke`, `disable`; audit log both sides
5. **Relock policy** — signed policy field, local caps
6. **(Phase 2) Lease store** — survives lock; serve path bound to `GrantCaller`
7. **(Phase 2) Hub renewer + revoke** — `abra lease grant … --ttl` (default 7d)

## Ops notes

```sh
# Optional: create/show device fingerprint (hidden; does not enable unlock)
abra remote whoami

# Enroll a paired receiver (requires ABRA_REMOTE_UNLOCK=1; network in PR 3)
abra remote enroll mini
```

Private keys and wrap keys are never printed, logged, or returned in errors. Prefer
`ABRA_DIR` overrides in tests; never commit `remote/*`.
