# Linux headless (SSH + systemd --user)

Guide for running abracadabra on a headless Linux box over SSH with the
per-user **abra-agent** systemd unit. See also [CROSS-PLATFORM.md](./CROSS-PLATFORM.md).

## Install

```bash
npm install -g @userdefault/abracadabra   # Node 20+
```

Find the node binary and package paths used by the agent unit (they must match
the `abra` CLI — see [Peer check / ExecStart](#peer-check--execstart)):

```bash
NODE="$(readlink -f "$(command -v node)")"
PKG="$(npm root -g)/@userdefault/abracadabra"
SERVER="$PKG/dist/agent/server.js"
# User-prefix installs: ~/.npm-global, ~/.local — use that prefix's npm root -g
# nvm / mise: resolve the same node that runs `abra`, not a different toolchain
```

Copy and enable the user unit:

```bash
mkdir -p ~/.config/systemd/user
cp "$PKG/packaging/linux/abra-agent.service" ~/.config/systemd/user/
# Edit ExecStart= to $NODE $SERVER (absolute paths)
systemctl --user daemon-reload
systemctl --user enable --now abra-agent

# So the user manager (and abra-agent) survive logout / run without a GUI seat:
sudo loginctl enable-linger "$USER"
```

PolKit policy (graphical desktop reveals; optional for passphrase-file headless):

```bash
# From a git checkout, or after locating packaging/ in the npm package:
sudo scripts/install-polkit.sh
# → installs packaging/linux/dev.abracadabra.policy
```

## Peer check / ExecStart

Sensitive agent ops (`unlock`, `unlock.key`, `vault.load`, `vault.save`, `grant.*`)
authorize the connecting peer via socket inode + `ss -xpn` + `/proc/<pid>/…`
([`src/agent/peer.ts`](../src/agent/peer.ts)). The peer must be the **abra CLI**:

1. Peer `exe` realpath == agent `process.execPath` realpath (same **node** binary)
2. Peer argv[1] realpath == this package’s `dist/index.js` (same install as
   `dist/agent/server.js` via `resolveAbraCliEntrypoint`)

So `ExecStart=` must use the same node that runs `abra`, and `server.js` from
the same `@userdefault/abracadabra` install as the `abra` bin. Mismatched nvm
vs `/usr/bin/node`, or a second copy of the package → `forbidden_peer`.

## Hardening caveat (user namespaces)

**Do not** set `PrivateTmp`, `ProtectSystem`, `ProtectHome`, `PrivateUsers`, or
`ReadWritePaths` / `ReadOnlyPaths` / `InaccessiblePaths` in a systemd **--user**
unit. Those options imply a user/mount namespace; inside it the peer-PID lookup
cannot see the caller, so every sensitive request fails closed:

```text
forbidden_peer reason=peer_pid_unresolved
```

The shipped unit keeps fail-closed peer checks and uses only namespace-safe
hardening: `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`,
`LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`,
`SystemCallArchitectures=native`, `UMask=0077`, `LimitCORE=0`,
`RuntimeDirectory=abra`.

- **AF_UNIX** — agent socket + D-Bus (Secret Service / gdbus sleep watch)
- **AF_NETLINK** — `ss` sock_diag used by the peer check (without it → `ss_failed`)

`MemoryDenyWriteExecute` is omitted (Node/V8 JIT).

## Migrate keytar → passphrase-file over SSH

PolKit defaults (`allow_any=no`) are unchanged — seatless SSH cannot approve
migrate via the policy. One-time path (do **not** persist in units or shell rc):

```bash
ssh -t <host> 'ABRA_AUTH=password abra keystore migrate --to passphrase-file'
```

Then unlock (needs a TTY for the hidden passphrase prompt):

```bash
ssh -t <host> abra unlock
```

## Keystore auto-detect

On Linux, when `ABRA_KEYSTORE` is unset and `<ABRA_DIR>/master.key.enc` exists,
both CLI and agent select `passphrase-file`. Explicit `ABRA_KEYSTORE` always
wins. Darwin / Windows never auto-detect.

If you set a custom `ABRA_DIR`, the **same** value must appear in the agent unit
and your shell so keystore backends match (agent mismatch check).

`export ABRA_KEYSTORE=passphrase-file` remains a valid explicit override.

## `abra agent status`

```bash
abra agent status              # one line; exit 0 unlocked / 1 locked / 2 not running
abra agent status --json
abra agent status --wait --timeout 600   # poll until unlocked (default timeout 300s)
```

Dependent units:

```ini
ExecStartPre=/usr/bin/abra agent status --wait --timeout 600
```

`status` does not require the abra CLI peer check and never prints secrets.

## Doctor

```bash
abra doctor
```

Shows keystore + auth backends and selection reasons (including
`auto-detected master.key.enc (linux)`).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `forbidden_peer` / `peer_pid_unresolved` | User-unit sandbox (`PrivateTmp` / `Protect*` / `PrivateUsers`) | Use shipped unit hardening; see [Hardening caveat](#hardening-caveat-user-namespaces) |
| `forbidden_peer` / `ss_failed` | `RestrictAddressFamilies` missing `AF_NETLINK` | Add `AF_NETLINK` (and keep `AF_UNIX`) |
| `forbidden_peer` / `exe_mismatch` or `argv_script_mismatch` | ExecStart node/package ≠ `abra` CLI | Align absolute paths (see [Peer check](#peer-check--execstart)) |
| `Keystore "keytar" does not use abra unlock` | No `master.key.enc` (or wrong `ABRA_DIR`) | Migrate, or set `ABRA_DIR` / `ABRA_KEYSTORE=passphrase-file` |
| PolKit denies migrate over SSH | Seatless session | One-time `ABRA_AUTH=password` (not persisted) |
| Unlock hangs / no prompt | No TTY | Use `ssh -t` |
| Agent locked after reboot | Expected | `abra unlock` again (or ExecStartPre `--wait` after unlock) |
| Agent not running after SSH logout | No linger | `sudo loginctl enable-linger "$USER"` |
