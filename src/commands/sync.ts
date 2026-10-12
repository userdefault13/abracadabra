import crypto from "node:crypto";
import os from "node:os";
import type { Command } from "commander";
import { loadVault, saveVault } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { promptHidden, promptTtyLine } from "../core/prompt.js";
import { createEphemeralTls } from "../core/tls-ephemeral.js";
import { generatePin } from "../core/pin.js";
import { getOrCreateSyncIdentity, publicIdentity } from "../sync/identity.js";
import { describeRoles, findPeer, parseRole, removePeer, validatePeerName } from "../sync/peers.js";
import {
  pairConnect,
  pairListen,
  PAIR_DEFAULT_PORT,
  PAIR_DEFAULT_TTL_MS,
  type PairDeps,
  type PairListenInfo,
  type PairResult,
} from "../sync/pair.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

export type SyncDeps = PairDeps;

export async function ttyConfirm(question: string): Promise<boolean> {
  const answer = await promptTtyLine(question);
  return /^y(es)?$/i.test(answer.trim());
}

export function defaultSyncDeps(): SyncDeps {
  return {
    authenticate: (reason) => authenticate(reason),
    loadVault,
    saveVault,
    confirm: ttyConfirm,
    // allowHeadless:false — the CI vault passphrase must never stand in for a PIN.
    promptPin: (q) => promptHidden(q, process.stderr, { allowHeadless: false }),
    createTls: createEphemeralTls,
    generatePin,
    hostname: () => os.hostname(),
    now: () => Date.now(),
    randomBytes: (n) => crypto.randomBytes(n),
    log: (line) => console.log(line),
  };
}

function printIdentity(vault: Vault, deps: SyncDeps, opts: { json?: boolean; created: boolean }) {
  const pub = publicIdentity(vault.syncIdentity!);
  if (opts.json) {
    deps.log(JSON.stringify({ ...pub, createdAt: vault.syncIdentity!.createdAt, created: opts.created }, null, 2));
    return;
  }
  if (opts.created) deps.log(green("✓ created this vault's sync identity"));
  deps.log(`id:          ${pub.id}`);
  deps.log(`fingerprint: ${bold(pub.fingerprint)}`);
}

export async function cmdSyncWhoami(opts: { json?: boolean }, deps: SyncDeps = defaultSyncDeps()): Promise<void> {
  const current = await deps.loadVault();
  if (current.syncIdentity) {
    getOrCreateSyncIdentity(current); // validates shape
    printIdentity(current, deps, { json: opts.json, created: false });
    return;
  }
  await deps.authenticate("abracadabra: create this vault's sync identity");
  const { vault, created } = getOrCreateSyncIdentity(await deps.loadVault(), { now: deps.now() });
  if (created) await deps.saveVault(vault);
  printIdentity(vault, deps, { json: opts.json, created });
}

export async function cmdSyncPeers(opts: { json?: boolean }, deps: SyncDeps = defaultSyncDeps()): Promise<void> {
  const vault = await deps.loadVault();
  const peers = Object.entries(vault.syncPeers ?? {}).sort(([, a], [, b]) => a.name.localeCompare(b.name));
  if (opts.json) {
    deps.log(
      JSON.stringify(
        peers.map(([id, p]) => ({
          id,
          name: p.name,
          role: p.role,
          idFingerprint: p.idFingerprint,
          pairedAt: p.pairedAt,
          lastAddress: p.lastAddress ?? null,
          ed25519: p.ed25519,
          x25519: p.x25519,
        })),
        null,
        2,
      ),
    );
    return;
  }
  if (peers.length === 0) {
    deps.log(dim("No paired peers — pair with: abra sync pair --listen  (or abra sync pair <host:port> --fingerprint <fp>)"));
    return;
  }
  for (const [, p] of peers) {
    const roleText = p.role === "source" ? "source (pushes to this machine)" : "receiver (this machine pushes to it)";
    deps.log(`${bold(p.name)}  ${roleText}`);
    deps.log(dim(`  id ${p.idFingerprint} · paired ${new Date(p.pairedAt).toLocaleString()}${p.lastAddress ? ` · last ${p.lastAddress}` : ""}`));
  }
}

export async function cmdSyncUnpair(
  nameOrId: string,
  opts: { yes?: boolean },
  deps: SyncDeps = defaultSyncDeps(),
): Promise<void> {
  const before = await deps.loadVault();
  const found = findPeer(before, nameOrId);
  if (!found) throw new Error(`no paired peer named "${nameOrId}" — see: abra sync peers`);
  if (!opts.yes) {
    const ok = await deps.confirm(`Remove peer "${found.peer.name}" (${found.peer.idFingerprint})? [y/N] `);
    if (!ok) {
      deps.log(dim("Aborted — nothing changed"));
      return;
    }
  }
  await deps.authenticate(`abracadabra: remove sync peer ${found.peer.name}`);
  const { vault, removed } = removePeer(await deps.loadVault(), found.id);
  await deps.saveVault(vault);
  deps.log(green(`✓ unpaired "${removed.peer.name}" (${removed.peer.idFingerprint})`));
}

function printListening(info: PairListenInfo, deps: SyncDeps) {
  deps.log(green("✦ abra sync pairing listener"));
  deps.log(`  role:             ${describeRoles(info.role)}`);
  deps.log(`  PIN:              ${bold(info.pin)}`);
  deps.log(`  TLS fingerprint:  ${info.tlsFingerprint}`);
  deps.log(`  this identity:    ${info.identityFingerprint}${info.identityCreated ? dim(" (new — saved only if pairing completes)") : ""}`);
  deps.log(`  expires:          ${new Date(info.expiresAt).toLocaleString()}`);
  const addrs = info.addresses.length > 0 ? info.addresses : ["<this-machine-ip>"];
  for (const addr of addrs) {
    const hostPart = addr.includes(":") ? `[${addr}]` : addr;
    deps.log(`  connect:          abra sync pair ${hostPart}:${info.port} --fingerprint ${info.tlsFingerprint}`);
  }
  deps.log(dim("\nNothing is synced by pairing — only identity public keys are exchanged."));
  deps.log(dim("Waiting for the other machine… Ctrl+C to stop"));
}

function printResult(result: PairResult, deps: SyncDeps) {
  const verb = result.action === "add" ? "paired with" : result.action === "update" ? "re-paired with" : "replaced and paired with";
  deps.log(green(`✓ ${verb} "${result.peer.name}" (${result.peer.idFingerprint})`));
  if (result.replaced) {
    deps.log(dim(`  replaced previous "${result.replaced.name}" (${result.replaced.idFingerprint})`));
  }
  deps.log(dim(`  ${describeRoles(result.myRole)}`));
  if (!result.peerSaved) {
    deps.log(
      yellow("⚠ the peer did not acknowledge its save — it may not have saved; run abra sync peers on both machines"),
    );
  }
}

export interface SyncPairCliOptions {
  listen?: boolean;
  port?: string;
  bind?: string;
  ttl?: string;
  role?: string;
  fingerprint?: string;
  name?: string;
  replace?: boolean;
}

export async function cmdSyncPair(
  target: string | undefined,
  opts: SyncPairCliOptions,
  deps: SyncDeps = defaultSyncDeps(),
): Promise<PairResult> {
  const role = opts.role !== undefined ? parseRole(opts.role) : undefined;
  if (opts.name !== undefined) validatePeerName(opts.name);

  if (opts.listen) {
    if (target) throw new Error("pass either --listen or <host:port>, not both");
    if (opts.fingerprint) throw new Error("--fingerprint is for the connecting side");
    const port = opts.port !== undefined ? Number(opts.port) : PAIR_DEFAULT_PORT;
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`invalid --port ${opts.port}`);
    const ttlSec = opts.ttl !== undefined ? Number(opts.ttl) : PAIR_DEFAULT_TTL_MS / 1000;
    if (!Number.isFinite(ttlSec) || ttlSec <= 0 || ttlSec > 3600) {
      throw new Error("--ttl must be between 1 and 3600 seconds");
    }
    const result = await pairListen(
      {
        port,
        bind: opts.bind,
        ttlMs: Math.round(ttlSec * 1000),
        role,
        name: opts.name,
        replace: opts.replace === true,
        onListening: (info) => printListening(info, deps),
      },
      deps,
    );
    printResult(result, deps);
    return result;
  }

  if (!target) throw new Error("pass --listen on one machine and <host:port> --fingerprint <fp> on the other");
  if (opts.port !== undefined || opts.bind !== undefined || opts.ttl !== undefined) {
    throw new Error("--port/--bind/--ttl only apply with --listen (put the port in <host:port>)");
  }
  const result = await pairConnect(
    {
      target,
      fingerprint: opts.fingerprint ?? "",
      role,
      name: opts.name,
      replace: opts.replace === true,
    },
    deps,
  );
  printResult(result, deps);
  return result;
}

function fail(err: unknown): never {
  console.error(red(`✗ ${err instanceof Error ? err.message : String(err)}`));
  process.exit(1);
}

export function registerSyncCommands(program: Command): void {
  const sync = program
    .command("sync")
    .description("(preview) Pair this vault with other machines for one-way project fan-out");

  sync
    .command("pair [target]")
    .description("Pair with another machine: one side runs --listen, the other connects to <host:port>")
    .option("--listen", "wait for the other machine to connect (prints PIN + TLS fingerprint)")
    .option("--port <number>", `listen port (with --listen; default ${PAIR_DEFAULT_PORT})`)
    .option("--bind <ip>", "listen address (with --listen; default 0.0.0.0)")
    .option("--ttl <seconds>", `listener lifetime (default ${PAIR_DEFAULT_TTL_MS / 1000})`)
    .option("--role <role>", "this machine's role: source (pushes) or receiver; listener default: source")
    .option("--fingerprint <fp>", "listener TLS fingerprint (required when connecting)")
    .option("--name <name>", "local name for the peer (default: its hostname)")
    .option("--replace", "overwrite an existing peer with the same name but a different identity")
    .action(async (target: string | undefined, opts: SyncPairCliOptions) => {
      try {
        await cmdSyncPair(target, opts);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  sync
    .command("whoami")
    .description("Show this vault's sync identity id + fingerprint (creates it if missing)")
    .option("--json", "JSON output (public keys only)")
    .action(async (opts: { json?: boolean }) => {
      try {
        await cmdSyncWhoami(opts);
      } catch (err) {
        fail(err);
      }
    });

  sync
    .command("peers")
    .description("List paired peers (name, role, identity fingerprint, last address)")
    .option("--json", "JSON output (includes public keys)")
    .action(async (opts: { json?: boolean }) => {
      try {
        await cmdSyncPeers(opts);
      } catch (err) {
        fail(err);
      }
    });

  sync
    .command("unpair <nameOrId>")
    .description("Remove a paired peer")
    .option("--yes", "skip the confirmation prompt")
    .action(async (nameOrId: string, opts: { yes?: boolean }) => {
      try {
        await cmdSyncUnpair(nameOrId, opts);
      } catch (err) {
        fail(err);
      }
    });
}
