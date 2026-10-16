# abra sync (preview): pairing + receiver inbox

`abra sync` will fan selected projects out from one **source** machine (e.g. your
MacBook, the source of truth) to paired **receiver** machines (e.g. Tailscale
peers). It is being built in phases. Phases 1–2 pair machines and let a receiver
accept sealed bundles; **there is no sender command yet** (`abra sync push`
arrives in Phase 3). No project, var, or secret crosses the wire during pairing.

| Phase | What |
|-------|------|
| 1 (done) | Device identity keys, `abra sync pair`, peers table, safety-code check |
| **2 (this)** | Receiver inbox in `abra-agent`; bundles sealed to a peer's X25519 key; `abra sync accept`, `abra sync inbox` |
| 3 | `abra sync push -p <proj> --hosts a,b` — one approval per batch, per-host results |
| 4 | `--tailnet` peer discovery via `tailscale status --json` |
| 5 | Explicit `--theirs` / `--allow-deletes` against a per-peer base (receiver-wins stays default) |

## Device identity

Each vault gets its own identity the first time you pair or run `abra sync whoami`:

- an **Ed25519** signing key (proves who you are during pairing; signs bundles you send)
- an **X25519** key-agreement key (bundles sent to you are sealed to it)
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

The inbox enforces roles: it only accepts bundles from peers this machine has
paired as `source`. A peer paired as `receiver` is refused even with a valid
signature, and a receiver never pushes back.

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

## Receiver inbox (Phase 2)

A receiver runs an HTTPS listener inside **abra-agent** (`abra agent`) that
accepts bundles from paired sources. It is **off by default** and only runs
while both are true: the inbox is enabled **and** at least one peer is paired as
`source`.

```sh
abra sync inbox --enable                     # approve → listen on this machine's Tailscale IPv4, port 7333
abra sync inbox --enable --bind 100.64.0.5 --port 7444
abra sync inbox --disable
abra sync inbox --status [--json]            # enabled / bind / port / listening / queued
```

- **Bind:** default is the Tailscale IPv4 from `tailscale ip -4` (re-detected each
  time the listener starts). If Tailscale isn't available, `--enable` refuses
  unless you pass `--bind <ip>`, and the agent stays off rather than falling
  back. It never defaults to `0.0.0.0` (an explicit `--bind 0.0.0.0` works, with a warning).
- **Endpoint:** `POST /v1/sync/inbox`, `Content-Type: application/json`, body ≤ 8 MiB,
  30 requests/min per remote IP. The response is only
  `{"status":"applied"|"queued"|"rejected","reason"?}`, never vault data.
  Authentication failures (unknown sender, wrong role, bad signature, wrong
  recipient) all answer `unauthorized`; the agent log records the exact reason,
  never contents.
- **Agent lifecycle:** the listener starts with the agent and stops with it. On
  every unlock the agent re-reads the inbox settings from the vault and applies
  queued bundles that match an auto rule. Without `--enable` the agent behaves
  exactly as before.

### What happens to a bundle

| Agent state / policy | Result |
|----------------------|--------|
| unlocked + matching **auto** rule | verified against the vault, decrypted, merged → `applied` |
| locked, or no auto rule | the **still-sealed** envelope goes to the queue → `queued` |
| unknown sender, sender paired as receiver, bad signature, wrong recipient, createdAt outside ±10 min, replayed bundle id, reserved/duplicate project names, too large, inbox full | `rejected` |

Merges use the same scoped merge as `abra usb sync --project` / LAN `--project`:
**receiver wins**. New projects and new keys are added; a key whose value
differs keeps this machine's value; nothing is ever deleted. Only the projects
named in the bundle are touched. Like existing scoped sync, no per-peer base is
recorded (Phase 5 adds explicit `--theirs` / `--allow-deletes` against a base).

Queued bundles live in `~/.abracadabra/sync-inbox/queue/<bundleId>` (files 0600,
dirs 0700, at most 64 bundles / 64 MiB). They are never decrypted to disk.

```sh
abra sync inbox [--json]                 # from, bundle id, projects, createdAt, verified?
abra sync inbox --apply <id|all>         # approve → verify, decrypt, merge, delete; prints per-project counts
abra sync inbox --reject <id|all>        # delete without applying
```

`--apply` prints only names and counts, e.g. `app: 1 added, 1 kept local` or
`other: new project, 3 added`. Bundles that no longer verify (e.g. the source was
unpaired) stay queued and the command exits non-zero. There is no freshness
limit on applying a queued bundle; freshness is only checked when it arrives.

## Accept policy

```sh
abra sync accept --list [--json]                 # (also the default with no options)
abra sync accept --from mbp -p web,api --auto    # auto-apply these projects from mbp
abra sync accept --auto                          # auto-apply everything from every source
abra sync accept --from mbp -p secrets           # always queue these for manual review
abra sync accept --from mbp -p web,api --remove
```

Each rule is `{from: <peer id> | "*", projects: [...] | "*", auto}`. Every change
requires approval. `--from` must name a peer paired as `source`; leave it out to
mean all sources. Leave out `-p` to mean all projects.

- A rule matches when `from` matches the sender and its projects cover **every**
  project in the bundle. Bundles that are only partly covered are queued whole.
- If a matching rule has `auto: false`, the bundle is queued, even when an auto
  rule also matches.
- If no rule matches, the bundle is **queued**, never applied and never rejected.
- Unpairing a peer removes its rules.

## Envelope format (abra-sync-seal-v1)

```
{ v: 1, from, to, bundleId, createdAt, projects: [names], epk, nonce, ct, sig }
```

1. The source builds `{v:1, projects}` from `extractScopedProjects` (projects only;
   reserved `__abra_*` / treasury names refused).
2. Ephemeral X25519 key `epk`; `shared = X25519(eph, receiver.x25519)` (the receiver's
   **pinned** key from pairing).
3. `key = HKDF-SHA256(shared, salt "abra-sync-seal-v1", info = lp("abra-sync-seal-v1",
   from, to, epk, receiver.x25519))`.
4. `ct = AES-256-GCM(key, 12-byte nonce, payload, AAD = header bytes) ‖ tag`, where
   the header bytes are `lp(domain, v, from, to, bundleId, createdAt, projects, epk, nonce)`.
5. `sig = Ed25519(source, lp("abra-sync-seal-v1/sig", header bytes, ct))`.

`lp` = u32-BE length-prefixed concatenation. The receiver checks: `to` is its own
id → `from` is a peer paired as `source` → signature against that peer's
**pinned** Ed25519 key → project names → createdAt within ±10 min → bundle id not
seen before. Only then does it decrypt. The decrypted project names must match
the signed header exactly. Full-vault bundles are never accepted.

### Locked agents: the trust mirror

The agent starts locked, so it can't read peers from the vault. It keeps a
**non-secret mirror** at `sync-inbox/anchors.json` with the inbox settings, its
own identity id, and the **public** Ed25519 keys of source peers. A locked agent
verifies signatures against this mirror and then queues. The mirror is never
trusted for apply: every apply (auto, on unlock, or `--apply`) verifies again
against the vault. The mirror is rewritten whenever inbox settings or peers
change (through the agent, `sync inbox --enable/--disable`, `pair`, `unpair`),
and deleted on restore.

### Replay cache

`sync-inbox/seen.json` maps bundle ids to createdAt for 24 h (max 4096
entries). It holds only bundle ids, so it works while the agent is locked. A bundle
is recorded when it is queued or applied (and on `--reject`). A replay of an
older bundle fails the ±10 min freshness check instead.

### TLS

The listener uses a self-signed certificate created once per device
(`sync-inbox/tls-{key,cert}.pem`, 0600, via openssl). TLS only hides envelope
metadata (ids, project names) from the network path, which Tailscale already
encrypts. **Authenticity comes from the Ed25519 envelope signature, not from
TLS**, and confidentiality of the projects comes from sealing to the receiver's
X25519 key. A sender doesn't need to trust the certificate for safety.

## Backups, restores and existing sync

`syncIdentity`, `syncPeers`, `syncAccept` and `syncInbox` are **device-local**:

- Scoped LAN/USB sync (`--project`) and inbox bundles only ever carry projects.
- Full-vault USB/LAN sync, USB backups and cartridge checkpoints strip these fields
  before sealing; merges always keep this machine's own values, and a LAN host
  never takes them from a peer's push. `sync-state.json` bases omit them.
- **Restoring** a vault (`abra usb restore`, `abra cartridge restore`) drops them
  and removes the inbox trust mirror, so a cloned vault never shares an identity
  with its origin. **Re-pair (and re-enable the inbox) after a restore.**

## Concurrency

Every write to `vault.enc` — CLI commands, the TUI, the web dash, MCP tools, LAN
host pushes, USB/LAN/cartridge restores and merges, and abra-agent's inbox
auto-apply — is a read-modify-write under one cross-process lock,
`~/.abracadabra/vault.lock`. The vault is re-loaded *inside* the lock and saved
atomically (tmp file + rename), so an inbox auto-apply that races
`abra set` (or two CLI commands) can't drop either change.

- Prompts (Touch ID, passphrase, PIN, conflict choices, safety codes) and network
  waits happen **before** the lock is taken; it is held for milliseconds.
- If abra-agent idle-locks between the warm unlock and the locked save, the save
  path fails fast with `agent locked during save — rerun` (it does **not** unlock
  or fall back to the keystore while holding `vault.lock`). Unlock and retry.
- Merges (`abra usb sync`, LAN sync, inbox `--apply`) are recomputed on the
  freshly loaded vault. If the conflicts or project deletions you approved no
  longer match, the sync stops without writing — re-run it.
- A LAN host merges a peer's push with edits made on the host since the peer
  pulled, and refuses the push (409) if they conflict.
- A waiter gives up after ~10 s with an error naming the holder's pid and the
  lock's age. A lock whose process died, or that is older than 30 s, is broken
  automatically (rename aside, re-check token, then discard — so two waiters
  cannot both break the same lock and both proceed). A holder that lost its lock
  that way refuses to write.

## Threat notes

- The safety-code comparison is what defeats a man-in-the-middle; the TLS
  fingerprint + PIN keep strangers out of the pairing window. Compare the words
  over a trusted channel (both screens in front of you, or a voice call).
- Tailscale ACLs are defense in depth, not a replacement for pairing: pairing
  binds *vault identities*, not network addresses (`lastAddress` is a hint only).
- Identity private keys never leave the encrypted vault. Pairing never reads or
  sends projects, vars, connections, passkeys or API keys.
- Bind the listener to the interface you mean (`--bind`) and keep `--ttl` short.

### Inbox threat model

- **Network attacker / stranger on the tailnet:** can reach the port, but without
  a paired source's Ed25519 key cannot get anything queued or applied. Size
  limits, a per-IP rate limit, header/request timeouts and a bounded queue cap
  the resources they can consume.
- **Captured envelope:** it is sealed to one receiver's X25519 key, useless
  elsewhere, and a resend is rejected by the replay cache or the ±10 min window.
- **Compromised source:** it can only *add* projects/keys to the receiver within
  the accept policy. Receiver-wins means it can't overwrite or delete existing
  values. Keep auto rules narrow (`--from`, `-p`) and review the rest with
  `abra sync inbox`.
- **Receiver compromise:** a receiver has no code path that sends anything back;
  the inbox only answers the HTTP request with a status.
- **Same-user local attacker:** can edit `anchors.json` or the queue, but that only
  affects what gets queued. Applying always re-verifies against the encrypted
  vault and needs approval or an unlocked agent. Such an attacker can already
  read the user's files, so this is out of scope.
