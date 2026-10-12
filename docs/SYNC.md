# abra sync (preview): pairing

`abra sync` will fan selected projects out from one **source** machine (e.g. your
MacBook, the source of truth) to paired **receiver** machines (e.g. Tailscale
peers). It is being built in phases; **Phase 1 only pairs machines — nothing
syncs yet.** No project, var, or secret crosses the wire during pairing.

| Phase | What |
|-------|------|
| **1 (this)** | Device identity keys, `abra sync pair`, peers table, safety-code check |
| 2 | Receiver inbox in `abra-agent`; bundles sealed to a peer's X25519 key; `abra sync accept` |
| 3 | `abra sync push -p <proj> --hosts a,b` — one approval per batch, per-host results |
| 4 | `--tailnet` peer discovery via `tailscale status --json` |
| 5 | Explicit `--theirs` / `--allow-deletes` against a per-peer base (receiver-wins stays default) |

## Device identity

Each vault gets its own identity the first time you pair or run `abra sync whoami`:

- an **Ed25519** signing key (proves who you are during pairing; later signs pushes)
- an **X25519** key-agreement key (Phase 2: bundles are sealed to it)
- a random **id** (UUID)

Keys are stored as base64 of the raw 32-byte values in the encrypted vault
(`syncIdentity`). Private keys are **never** written to any other file, logged,
printed, exported, or sent anywhere. There is no export command.

The **identity fingerprint** is `SHA-256("abra-sync-id-v1", ed25519, x25519)`
(length-prefixed), shown as 8 groups of 4 hex digits, e.g.
`81a0 1782 de85 5477 d98c c94b 11d6 35f0`.

```sh
abra sync whoami            # id + fingerprint (creates the identity if missing)
abra sync whoami --json     # public keys only
```

## Pairing

On the machine that should be the **source** (default role for the listener):

```sh
abra sync pair --listen                 # approve → prints PIN, TLS fingerprint, identity, connect command
abra sync pair --listen --bind 100.101.102.103 --port 7334 --ttl 300
```

On the other machine (it becomes the **receiver**):

```sh
abra sync pair 100.101.102.103:7334 --fingerprint <TLS fingerprint> [--name mbp]
# → approve, then type the PIN (hidden prompt; there is no --pin flag)
```

Both screens then show the peer's identity fingerprint, both roles, and the
**safety code** — 6 words plus the same code as 4 groups of 3 digits:

```
  safety code:     cobalt fiddle orbit radish tango ember
                   482 019 733 105
Do both screens show the same 6 words? [y/N]
```

Answer **y** on each machine only if the codes match. The pairing is saved only
when **both** sides confirm. A **n** (or no TTY, a timeout, or a mismatch) on
either side writes nothing on either side and exits non-zero.

### Options

| Flag | Side | Meaning |
|------|------|---------|
| `--listen` | listener | wait for the other machine |
| `--port <n>` | listener | default `7334` (`0` = any free port) |
| `--bind <ip>` | listener | default `0.0.0.0` (like `abra usb host`); restrict to e.g. your Tailscale IP |
| `--ttl <s>` | listener | listener lifetime, default 300 s (max 3600) |
| `--role source\|receiver` | both | **this** machine's role. Listener default: `source`. The connector always gets the opposite; an explicit conflicting `--role` aborts |
| `--fingerprint <fp>` | connector | **required**; full SHA-256 TLS fingerprint printed by the listener |
| `--name <name>` | both | local name for the peer (default: its hostname, sanitized to `[a-z0-9._-]`, ≤ 64) |
| `--replace` | both | allow replacing an existing peer that has the same name but a different identity |

### Roles

`role` in the peers table is what **the peer** is relative to this machine:

- `source` — it may push projects to me (I receive)
- `receiver` — I push projects to it

Phase 1 only records roles; nothing enforces them yet.

### Re-pairing rules

- Same peer id and keys → only `lastAddress` (and the name, if `--name` is given) are updated.
- Same name but a different identity → refused unless `--replace` (old vs new fingerprint shown).
- Same peer id but **different keys** → always refused (possible impersonation). If that
  machine was genuinely reset, run `abra sync unpair <name>` first.
- Changing a peer's role → `abra sync unpair` first.
- A peer presenting **this vault's own identity** (e.g. a cloned vault) → refused.

### Other commands

```sh
abra sync peers [--json]          # name, role, identity fingerprint, pairedAt, lastAddress
abra sync unpair <name|id> [--yes]
```

## Protocol (abra-sync-pair-v1)

1. **Approval first.** Each side calls the platform approval (Touch ID / PolKit /
   passphrase) *before* listening or connecting.
2. **TLS + PIN.** The listener uses a fresh self-signed cert (same as `abra usb
   host`) and a 6-digit PIN. The connector verifies the full TLS fingerprint on the
   raw socket **before sending any byte**, then sends the PIN. 8 wrong PINs lock
   and close the listener; it also closes after its TTL or after one PIN-accepted
   session.
3. **Hello exchange.** Newline-delimited JSON over that socket. Each side sends
   `{protocol, id, name, ed25519, x25519, nonce (32 random bytes), role}`.
4. **Transcript + proof of possession.** Both compute
   `SHA-256` over the protocol id, the TLS cert fingerprint, and both hellos
   (keys, nonces, names, resolved roles; length-prefixed, listener first). Each
   side signs it with Ed25519 (domain-separated by side) and verifies the other's
   signature.
5. **Safety code.** `SHA-256("abra-sync-sas-v1", transcript)`; the first 6 bytes
   select 6 words from a fixed 256-word list (48 bits); the same 48 bits mod 10¹²
   are also shown as 12 digits.
6. **Confirm, then write.** Each side asks its own user, sends `confirm`, and
   waits for the other side's `confirm`. Only when both said yes does each side
   re-read its vault, add the peer, and save atomically (`saveVault`). Each then
   sends `saved`. If the peer's `saved` never arrives you'll see
   *"the peer did not acknowledge its save — run abra sync peers on both machines"*.

## Backups, restores and existing sync

`syncIdentity` and `syncPeers` are **device-local**:

- Scoped LAN/USB sync (`--project`) only ever carries projects.
- Full-vault USB/LAN sync, USB backups and cartridge checkpoints strip both fields
  before sealing; merges always keep this machine's own identity and peers, and
  a LAN host never takes them from a peer's push. `sync-state.json` bases omit them.
- **Restoring** a vault (`abra usb restore`, `abra cartridge restore`) drops them,
  so a cloned vault never shares an identity with its origin. **Re-pair after a
  restore.**

## Threat notes

- The safety-code comparison is what defeats a man-in-the-middle; the TLS
  fingerprint + PIN keep strangers out of the pairing window. Compare the words
  over a trusted channel (both screens in front of you, or a voice call).
- Tailscale ACLs are defense in depth, not a replacement for pairing: pairing
  binds *vault identities*, not network addresses (`lastAddress` is a hint only).
- Identity private keys never leave the encrypted vault. Nothing in Phase 1 reads
  or sends projects, vars, connections, passkeys or API keys.
- Bind the listener to the interface you mean (`--bind`) and keep `--ttl` short.
