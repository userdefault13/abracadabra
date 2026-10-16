# Remote unlock (hub-held unwrap key)

Status: **PR 5/7** — Relock policy (signed idle/max-age, local caps, CLI flags).
Feature flag: off by default (`ABRA_REMOTE_UNLOCK=1` to enable enroll / unlock listener).
Nothing new runs unless you invoke it. Julius approved both phases; bot lease
default TTL is **7 days**.

Design source: [REMOTE-UNLOCK-DESIGN.md](./REMOTE-UNLOCK-DESIGN.md).

## What PR 1–5 ship

| Piece | Path | Notes |
|-------|------|--------|
| Device key | `<abraDir>/remote/device-key.json` | Ed25519 + X25519, 0600 in a 0700 dir |
| Hub pin | `<abraDir>/remote/hub-pin.json` | Hub `deviceId` + public keys only |
| Unlock blob | `<abraDir>/remote/remote-unlock.blob` | AES-256-GCM_W(masterKey); AAD = deviceId + master-key fingerprint |
| Hub wrap | `syncPeers[id].unlockWrap` | Device-local with peers; stripped on export; cleared on unpair |
| Wire crypto | `src/remote/wire.ts` | Challenge + seal(W) + lock + Ed25519; 30s expiry |
| Relock policy | `src/remote/policy.ts` | Hub may shorten idle/max-age; receiver clamps to local caps |
| Nonce cache | `src/remote/nonce-cache.ts` | Single-use pending + used (in-memory) |
| Listener | `src/remote/listener.ts` | HTTPS `:7335` unlock/lock/status/enroll; Tailscale bind |
| Hub client | `src/remote/hub-client.ts` | unlock / lock / status / enroll HTTP clients |
| Audit log | `<abraDir>/remote/audit.log` | JSON lines: `ts`, `op`, `peer`, `result` (never values) |
| Agent | `src/agent/remote-unlock.ts` | Flag + (enrolled **or** unlocked for first enroll) |
| Feature flag | `ABRA_REMOTE_UNLOCK` | Must be `1` for enroll / unlock / lock / disable |
| CLI | `abra remote …` | `whoami`, `enroll`, `unlock`, `lock`, `status`, `revoke`, `disable` |

## Wire protocol (PR 3)

Port **7335**, bind **Tailscale IPv4 only** (same detect/bind pattern as the sync
inbox). Off unless `ABRA_REMOTE_UNLOCK=1` **and** enrolled (device key + hub pin +
blob).

1. Hub `POST /v1/remote/unlock` `{op:"challenge"}` → receiver returns a fresh
   32-byte nonce + ephemeral X25519 pub, signed with the **device key**.
2. Hub verifies against the enrolled device pub, returns `seal(ephemeral_pub, W)`
   plus an Ed25519 signature over `(from, peerId, nonce, expiresAt ≤ 30s, policy, seal)`.
3. Receiver verifies against `hub-pin.json` (works while locked), checks expiry +
   single-use nonce cache, unwraps the blob, hands the master key to the in-process
   unlock path. **W** and the master key buffers are zeroed after use.

Strict message size limits, schema validation, per-source-IP rate limit.
Logs: `op` / `peer` / `result` only — no wrap keys, master keys, or ciphertext.

## Relock policy (PR 5)

The signed unlock response includes a `policy` object:

```json
{ "idleSeconds": 300, "maxAgeSeconds": 3600 }
```

- **Units:** seconds (matches `ABRA_AGENT_IDLE_SECONDS` / `ABRA_AGENT_MAX_AGE_SECONDS`).
- **Receiver:** applies `min(requested, localCap)` per field. Omitted fields → local cap.
- **Local caps:** same as the agent — default idle **15m**, max age **8h**, overridable with
  `ABRA_AGENT_IDLE_SECONDS` / `ABRA_AGENT_MAX_AGE_SECONDS` on the receiver.
- **Hub can only shorten** timers, never lengthen them past the receiver's local caps.
- Invalid / non-positive values are rejected at parse or clamp time.
- Tampering with `policy` after signing fails signature verification (and seal AAD).

CLI (hub):

```sh
abra remote unlock --all --idle 5m --max-age 1h
```

`--keep-alive` is **not supported**. Re-unlock always requires a fresh Touch ID on the
hub (no silent re-unlock loop). The flag is refused with an explicit error.

## Enroll (PR 2)

Receiver (local unlock): mint wrap key `W`, write `remote-unlock.blob`, seal `W`
to the hub's X25519 key, pin hub pubs, forget `W`.

Hub (Touch ID via existing auth path): only paired peers with role **receiver**
may enroll; store `W` under `syncPeers[id].unlockWrap`.

Re-enroll: if the receiver master key changes, the blob fingerprint check fails
→ clear error **"re-enroll needed"**.

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

## CLI (PR 4–5)

| Command | Side | Auth | Notes |
|---------|------|------|--------|
| `abra remote enroll <peer>` | hub | Touch ID | Fetches offer over `:7335` `/v1/remote/enroll`; stores `W` + listener cert |
| `abra remote unlock --all\|--peers a,b` | hub | Touch ID once | Parallel per-peer unlock; optional `--idle` / `--max-age` |
| `abra remote lock --all\|--peers` | hub | none | Signed lock request (30s expiry) |
| `abra remote status` | hub | none | Enrolled / reachable / locked — no secrets |
| `abra remote revoke <peer>` | hub | Touch ID | Deletes `unlockWrap` via `updateVault` |
| `abra remote disable` | receiver | none | Deletes blob + hub pin; listener stops on reconcile |
| `abra remote whoami` | either | none | Public device fingerprint only |

Audit: both sides append JSON lines to `<abraDir>/remote/audit.log`
(`ts`, `op`, `peer`, `result`). Hub offline never breaks local unlock.

## PR plan (1–7)

1. **Device key + pinned hub key** — agent dir, 0600, fail-closed perms; tests
2. **Enroll** — create `W`, blob, seal `W` to hub; Touch ID on hub
3. **Wire protocol** — challenge/response, signatures, nonce cache, 30s expiry, tailnet listener
4. **CLI** — `unlock|lock|status --all|--peers`, `revoke`, `disable`; audit log both sides
5. **Relock policy** (this PR) — signed policy field, local caps, CLI flags, docs
6. **(Phase 2) Lease store** — survives lock; serve path bound to `GrantCaller`
7. **(Phase 2) Hub renewer + revoke** — `abra lease grant … --ttl` (default 7d)

## Setup

### Prerequisites

1. Hub and receivers paired (`abra sync pair`) with roles **source** (hub) / **receiver**.
2. Both machines on the same Tailscale tailnet.
3. Feature flag on both sides: `export ABRA_REMOTE_UNLOCK=1`.
4. Receiver running `abra-agent` (unlocked for first enroll).

### Enroll (once per peer)

```sh
# On the receiver (unlocked agent; flag set):
export ABRA_REMOTE_UNLOCK=1
# abra-agent must be listening so /v1/remote/enroll is reachable

# On the hub:
export ABRA_REMOTE_UNLOCK=1
abra remote whoami          # optional: show this device fingerprint
abra remote enroll mini     # Touch ID once; stores unlockWrap for peer "mini"
abra remote status
```

### Unlock / lock / policy

```sh
abra remote unlock --all
abra remote unlock --peers mini --idle 5m --max-age 1h
abra remote lock --all
abra remote status
```

Local unlock on each box (`abra unlock`) is unchanged and does not need the hub.

### Tailnet ACL (port 7335)

Remote unlock listens on **TCP 7335** bound to the Tailscale IPv4 only (same pattern
as the sync inbox on 7334). Open the port between hub and receivers in your
tailnet ACL, for example:

```json
{
  "action": "accept",
  "src": ["tag:abra-hub"],
  "dst": ["tag:abra-receiver:7335"]
}
```

Adjust tags/users to match your tailnet. Without this rule, enroll/unlock will
fail as unreachable. Do **not** expose 7335 on the public internet — bind is
tailnet-only by design.

### Rollback

1. **Disable on each receiver** (deletes blob + hub pin; listener stops):

   ```sh
   export ABRA_REMOTE_UNLOCK=1
   abra remote disable
   ```

2. **Revoke on the hub** (deletes `unlockWrap` — hub can no longer unlock that peer):

   ```sh
   export ABRA_REMOTE_UNLOCK=1
   abra remote revoke mini
   ```

3. **Feature flag off** — unset `ABRA_REMOTE_UNLOCK` (or set to anything other than
   `1`) on hub and receivers. Behaviour matches a build without remote unlock:
   local unlock / lock / agent idle timers only.

4. Optionally unpair (`abra sync unpair`) if you also want to drop the peer
   relationship; unpair clears `unlockWrap` as well.

Private keys and wrap keys are never printed, logged, or returned in errors. Prefer
`ABRA_DIR` overrides in tests; never commit `remote/*`.
