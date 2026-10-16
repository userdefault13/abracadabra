# abra: remote fleet unlock from the hub — design (architect)

Status: design only. No code, no secrets. Base: userdefault13/abracadabra main @ 67bb794.
Sources read: src/agent/{grants,protocol}.ts, src/sync/peers.ts, file tree of src/agent/* and src/sync/*.
PR #25 (inbox) not re-read here; assumptions about it are marked (guess).

## TLDR
Build **Option A, "hub-held unwrap key"**: each paired receiver keeps a wrapped copy of its own
master key on disk that it cannot open by itself. The hub (MBP) holds the matching unwrap key
inside its vault and, after a Touch ID tap, sends it over an authenticated, challenge-bound,
end-to-end-encrypted channel. Then add **Option B (scoped bot leases)** so bots like cryptoPnL
stop needing the full vault open at all.

## Key facts from the code (evidence)
- `abra-agent` holds the 32-byte master key in memory; `unlock.key` op takes it base64 over the
  local unix socket (protocol.ts). Locks on idle (15m) / max-age (8h).
- `GrantStore` (grants.ts) already gives per-project, per-binary (exe+dev+ino) reveal grants,
  TTL 60s..8h, in memory only, **cleared on every lock**. So grants today cannot outlive a lock.
- Sync identity (Ed25519 + X25519) is stored **inside the vault** (`vault.syncIdentity`,
  `vault.syncPeers`, peers.ts). **Crux:** a locked receiver cannot read its own sync private keys,
  so it cannot authenticate or decrypt a remote unlock with them. Any design needs a small
  **device key outside the vault** (0600 file, or TPM / Secure Enclave where available).
- Pairing (PR #24) already gives: mutual pinned public keys, 6-word SAS, roles source/receiver,
  impersonation refusal on key change, ports 7333/7334 over Tailscale.

## Constraints
Must
- MBP is source of truth and the only issuer; Touch ID on the MBP is the approval.
- Passphrase never leaves any machine, in clear or otherwise. (Design never sends a passphrase at all.)
- Receivers keep their passphrase-file keystore; local `abra unlock` keeps working unchanged.
- Only paired peers (PR #24) can be unlocked; per-peer revocation; replay protection.
- Hub offline → nothing breaks that works today (local unlock still works).
Should
- One command / one tap unlocks all or selected peers (`--all`, `--peers a,b`), mirroring sync UX.
- Bots get least privilege (project-scoped) rather than full vault.
- Every remote unlock is logged on both sides (no secret values).
Won't
- No cloud relay, no third-party KMS, no persistent plaintext master key on receiver disk.
- No auto-unlock without the hub (that would be Option C, explicitly a separate choice).

## Options

### A. Hub-held unwrap key (recommended core)
Setup (per peer, once, at `abra sync pair` or new `abra remote enroll <peer>`, Touch ID on hub +
one local unlock on the receiver):
1. Receiver creates a **device key pair** stored outside the vault (0600 in agent dir; TPM-sealed
   later). Public half pinned by hub during enroll (bound to the existing SAS-verified Ed25519 id).
2. Receiver generates random wrap key W, writes `remote-unlock.blob = AEAD_W(masterKey)` to disk,
   then sends W to the hub sealed to the hub's X25519 key. Receiver forgets W.
3. Hub stores W in its vault under the peer record (`syncPeers[id].unlockWrap`), encrypted at rest.
Unlock (`abra remote unlock --all|--peers ...`):
1. Hub asks Touch ID once for the batch.
2. Receiver agent (listening on a tailnet-only port, e.g. 7335, or reusing 7334) issues a fresh
   random nonce + its ephemeral X25519 pub, signed with its device key.
3. Hub verifies the signature against the pinned device key, returns
   `seal(ephemeral_pub, W)` + hub Ed25519 signature over (peerId, nonce, expiresAt ≤ 30s, policy).
4. Receiver verifies hub signature (hub pubkey pinned at pairing; usable while locked because the
   pin is copied outside the vault at enroll), unwraps blob, calls existing in-process
   `unlock.key` path, discards W. Applies policy (idle/max-age) from the signed message,
   capped by local config.
- Replay: single-use nonce from receiver, short expiry, ephemeral key per attempt.
- Revocation: `abra remote revoke <peer>` deletes W on hub (instant: hub can't unlock it anymore);
  `abra sync unpair` implies revoke. Receiver-side `abra remote disable` deletes the blob.
  Passphrase change on receiver → blob invalid → re-enroll (detect and say so).
- Stolen receiver disk: blob is useless without W; W lives only in the hub vault.
- Compromised hub (unlocked + Touch ID): can unlock peers — same trust as today's sync push.
- Hub offline: no remote unlock; local unlock works as now. No degradation.
Tradeoffs: + real fix for "walk to each box", + no passphrase moves, + revocation is one delete.
– full-vault unlock (bots still see everything), – new listener port, – device key file is new
attack surface (but alone it can only *ask*, not unlock).

### B. Scoped bot leases (per-project, pushed from hub)
Hub pushes a **lease**: one project's secrets re-encrypted to the receiver device key, signed,
with an expiry (e.g. 24h–7d) and a binding to a binary (exe+dev+ino, reusing GrantCaller).
Agent serves only that project to that binary, even while the main vault is locked.
Requires grants to survive lock (new "lease store" separate from GrantStore, which stays as is).
Renewal: hub auto-renews before expiry (scheduled job, Touch ID policy: once per enroll, or per
renew — Julius's choice). Revocation: hub sends revoke + lease simply expires; worst case = TTL.
Tradeoffs: + least privilege, + cryptoPnL never needs the full vault open, + survives 8h lock.
– secrets for that project sit (encrypted to a disk key) on the receiver for the lease life,
– renewals need the hub online or leases expire (bots stop at expiry — fail closed),
– more code (lease format, renewer, agent serve path). Builds on PR #25 inbox (guess: reuse its
signed-envelope + apply path).

### C. Longer timers / local auto-unlock (baseline, no hub)
Raise idle/max-age on omarchywin, or let the agent auto-unlock at boot from the local keystore
(passphrase-file / systemd-creds / TPM).
Tradeoffs: + trivial, + works with hub offline. – anyone with that box's disk/user gets the vault,
– no central approval or revocation, – contradicts "Touch ID on hub is approval".
Wins only if a box is low-value or the hub is often unreachable.

## Matrix
| | Fit | Reliability | Ops cost | Complexity | Risk |
|---|---|---|---|---|---|
| A unwrap key | high (exact ask) | needs hub up to unlock; local fallback | low | medium | low–med |
| B bot leases | high for bots | survives locks; fails closed at expiry | medium (renewer) | high | low (scoped) |
| C timers/auto | low | high | none | very low | high |

## Recommendation (phased) + rollback
Phase 1: A for full-fleet unlock (`abra remote unlock --all`), off by default, opt-in per peer.
Phase 2: B for cryptoPnL and other bots; then shorten full-vault timers again.
Auto-relock policy: keep receiver idle 15m / max 8h locally; hub may request a shorter
policy, never longer than local cap. Add `abra remote lock --all` (no Touch ID needed to lock).
Optional "keep-alive": hub re-unlocks on lock events only with a fresh Touch ID (no silent loop).
Rollback: `abra remote disable` on each receiver (deletes blob) + `abra remote revoke` on hub;
feature flag off → behaviour identical to 1.0.7.

## PR breakdown (after sync PR #25 lands; vault write lock goes first)
1. **Device key + pinned hub key outside vault** (agent dir, 0600, fail-closed perms check; tests).
2. **Enroll**: `abra remote enroll <peer>` — create W, blob, seal W to hub, store in peer record;
   Touch ID on hub; re-enroll detection after passphrase change.
3. **Wire protocol**: challenge/response messages, signatures, nonce cache, 30s expiry,
   tailnet-only listener; fuzz + replay tests. No secrets in logs.
4. **CLI**: `abra remote unlock|lock|status --all|--peers`, `revoke`, `disable`; audit log both sides.
5. **Relock policy**: signed policy field, local caps, doc.
6. (Phase 2) **Lease store** in agent (survives lock), lease format, serve path bound to GrantCaller.
7. (Phase 2) **Hub renewer + revoke**, `abra lease grant <project> --peer <p> --bin <path> --ttl`.

## Handoff
Abracadabra CoS routes: cursor-cli on MBP builds PRs 1–5 in a new worktree each; merges need
Julius's "merge N". Home Infra CoS: opens tailnet ACL for the new port on omarchywin.
Open questions for Julius: (1) Touch ID once per batch OK? (2) Is phase 2 (bot leases) wanted now
or after A? (3) Max lease length for cryptoPnL.
Guess to verify: what exactly the "passphrase-file" keystore stores on omarchywin — if it holds
the passphrase itself on disk, C is effectively already the security level there and A's
benefit is mostly UX + central revocation.
