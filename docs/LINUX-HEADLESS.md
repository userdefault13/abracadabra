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

Then unlock (needs a TTY for the hidden passphrase prompt). Non-interactive
**Tailscale SSH** often omits mise from `PATH` and leaves `XDG_RUNTIME_DIR`
unset — use the PATH form (or `packaging/linux/abra-unlock`); see
[Tailscale SSH](#tailscale-ssh--non-interactive-ssh). `XDG_RUNTIME_DIR` is
handled via a validated `/run/user/<uid>` fallback when unset.

```bash
ssh -t <host> 'PATH=$HOME/.local/share/mise/shims:$PATH abra unlock'
# or: ssh -t <host> ~/.local/bin/abra-unlock
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

Text and `--json` include how the socket path was chosen (`socketSource` /
`socketReason`: `XDG_RUNTIME_DIR`, `/run/user/<uid>` fallback, or
`ABRA_AGENT_SOCKET`).

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
`auto-detected master.key.enc (linux)`), plus an **abra-agent socket** line
(path + source + reason, or why the agent is disabled). When keystore was
auto-detected and the agent is locked or not running, doctor also warns about
systemd units that may fail with `vault locked` on restart — see
[Upgrading existing units](#upgrading-existing-units). Never prints secrets.

## Upgrading existing units

Once `master.key.enc` exists, Linux auto-detects `passphrase-file` when
`ABRA_KEYSTORE` is unset. Any existing systemd unit that runs `abra run …`
(or other vault I/O) **without** pinning `ABRA_KEYSTORE` will silently switch
from keytar to passphrase-file on upgrade. A process that is already running
is fine; a **restart** after idle lock, the 8h max-age, or reboot fails with
`vault locked` and no TTY.

Pick one transition path:

### 1. Pin keytar during the transition

Leave the keytar copy in place (`abra keystore migrate` without `--remove-old`
keeps it) and pin the backend in each unit that still expects keytar:

```ini
# systemctl --user edit <unit>
[Service]
Environment=ABRA_KEYSTORE=keytar
```

Keytar still needs Secret Service / the session bus available to that unit.
Remove the pin (or switch to option 2) once you are ready for passphrase-file.

### 2. Switch the unit to passphrase-file + wait for unlock

Make the unit wait for a human `abra unlock` instead of failing immediately:

```ini
# systemctl --user edit my-abra-job.service
[Unit]
# Allow retries after unlock without hitting StartLimit
StartLimitIntervalSec=0

[Service]
# Optional but clear — auto-detect would pick this anyway once master.key.enc exists
Environment=ABRA_KEYSTORE=passphrase-file
# Absolute paths — same node/package as `abra` (see Peer check / ExecStart)
ExecStartPre=/usr/bin/abra agent status --wait --timeout 0
ExecStart=/usr/bin/abra run myproj -- /usr/bin/my-daemon
Restart=on-failure
RestartSec=60
```

Then unlock over SSH (Tailscale / non-interactive often needs mise on `PATH`):

```bash
ssh -t <host> 'PATH=$HOME/.local/share/mise/shims:$PATH abra unlock'
# or: ssh -t <host> ~/.local/bin/abra-unlock
```

`abra doctor` warns when auto-detect is active and the agent is locked or not
running so you can catch this before units restart.

## Tailscale SSH / non-interactive SSH

Non-interactive SSH (including **Tailscale SSH** without a TTY) often:

1. **Does not load shell rc** — so `mise` shims (and sometimes `~/.local/bin`)
   are missing from `PATH`, and `abra` may be `command not found`.
2. **Leaves `XDG_RUNTIME_DIR` unset** — older abracadabra builds then treated
   the agent as off even when `abra-agent` was running under systemd.

**PATH / finding `abra`:**

```bash
# One-shot: put mise shims on PATH for this remote command
ssh -t host 'PATH=$HOME/.local/share/mise/shims:$PATH abra unlock'

# Or install the small wrapper (from this package) and call it:
#   cp packaging/linux/abra-unlock ~/.local/bin/ && chmod +x ~/.local/bin/abra-unlock
ssh -t host ~/.local/bin/abra-unlock
```

Persistent options (pick what matches your shell):

| Approach | Notes |
|----------|--------|
| `~/.zshenv` | zsh reads this for **non-interactive** shells — good place for mise/`PATH` |
| `~/.bash_profile` / `~/.bashrc` | bash; non-interactive may skip `.bashrc` unless sshd/ForceCommand loads it |
| `~/.ssh/environment` | requires `PermitUserEnvironment` in `sshd_config`; **Tailscale SSH may not honor it** |

**`XDG_RUNTIME_DIR` / agent socket:** if unset, abracadabra falls back to
`/run/user/<uid>` when that path is a real directory (not a symlink), owned by
you, and mode `0700` (no group/other bits). That usually requires a logind
session or `sudo loginctl enable-linger "$USER"`. The agent unit sets
`XDG_RUNTIME_DIR` itself under systemd, so CLI and agent both land on
`/run/user/<uid>/abra/agent.sock`. Check with `abra agent status` or
`abra doctor`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `forbidden_peer` / `peer_pid_unresolved` | User-unit sandbox (`PrivateTmp` / `Protect*` / `PrivateUsers`) | Use shipped unit hardening; see [Hardening caveat](#hardening-caveat-user-namespaces) |
| `forbidden_peer` / `ss_failed` | `RestrictAddressFamilies` missing `AF_NETLINK` | Add `AF_NETLINK` (and keep `AF_UNIX`) |
| `forbidden_peer` / `exe_mismatch` or `argv_script_mismatch` | ExecStart node/package ≠ `abra` CLI | Align absolute paths (see [Peer check](#peer-check--execstart)) |
| `Keystore "keytar" does not use abra unlock` | No `master.key.enc` (or wrong `ABRA_DIR`) | Migrate, or set `ABRA_DIR` / `ABRA_KEYSTORE=passphrase-file` |
| PolKit denies migrate over SSH | Seatless session | One-time `ABRA_AUTH=password` (not persisted) |
| Unlock hangs / no prompt | No TTY | Use `ssh -t` with mise on PATH — see [Tailscale SSH](#tailscale-ssh--non-interactive-ssh) |
| Agent locked after reboot | Expected | `abra unlock` again (or ExecStartPre `--wait` after unlock) |
| Unit fails with `vault locked` after upgrade | Auto-detect switched keytar → passphrase-file; unit restarted while agent locked / down | See [Upgrading existing units](#upgrading-existing-units): pin `ABRA_KEYSTORE=keytar`, or `ExecStartPre=… agent status --wait`, then unlock |
| Agent not running after SSH logout | No linger | `sudo loginctl enable-linger "$USER"` |
| `abra: command not found` over Tailscale/non-interactive SSH | No mise/`PATH` in non-interactive session | `PATH=$HOME/.local/share/mise/shims:$PATH`, `~/.zshenv`, or `~/.local/bin/abra-unlock` — see [Tailscale SSH](#tailscale-ssh--non-interactive-ssh) |
| `Vault unlocked for this process only` while agent is running | `XDG_RUNTIME_DIR` unset and `/run/user/<uid>` missing/wrong mode/owner; or older abra | `abra agent status` / `abra doctor`; `loginctl enable-linger`; or `export XDG_RUNTIME_DIR=/run/user/$(id -u)` |
