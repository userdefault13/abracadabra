import crypto from "node:crypto";
import net from "node:net";
import os from "node:os";
import type { Command } from "commander";
import { loadVault, updateVault, VAULT_UNCHANGED } from "../core/vault.js";
import type { SyncAcceptRule, Vault } from "../core/vault.js";
import { abraDir } from "../core/paths.js";
import { authenticate } from "../platform/index.js";
import { promptHidden, promptTtyLine } from "../core/prompt.js";
import { createEphemeralTls } from "../core/tls-ephemeral.js";
import { generatePin } from "../core/pin.js";
import { agentInboxStatus, shouldTryAgent } from "../agent/client.js";
import type { AgentInboxStatusBody } from "../agent/protocol.js";
import { getOrCreateSyncIdentity, isUuid, publicIdentity } from "../sync/identity.js";
import { describeRoles, findPeer, parseRole, removePeer, validatePeerName } from "../sync/peers.js";
import {
  describeAcceptRule,
  parseProjectsOption,
  removeAcceptRules,
  upsertAcceptRule,
} from "../sync/accept.js";
import { EnvelopeError, trustFromVault, verifyEnvelope } from "../sync/envelope.js";
import { applyEnvelope, formatCounts, type ApplyResult } from "../sync/inbox.js";
import {
  INBOX_DEFAULT_PORT,
  InboxQueue,
  ReplayCache,
  syncAnchorsFromVault,
} from "../core/sync-inbox-store.js";
import { detectTailscaleIPv4 } from "../sync/tailscale.js";
import {
  pairConnect,
  pairListen,
  PAIR_DEFAULT_PORT,
  PAIR_DEFAULT_TTL_MS,
  type PairDeps,
  type PairListenInfo,
  type PairResult,
} from "../sync/pair.js";
import { isRemoteUnlockEnabled } from "../remote/feature.js";
import { revokePeerLeasesBestEffort } from "../remote/lease-revoke-peer.js";
import type { RemoteHttpsJsonFn } from "../remote/hub-client.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const red = (s: string) => `\x1b[31m${s}\x1b[0m`;

export interface SyncDeps extends PairDeps {
  /** Directory holding vault.enc and sync-inbox/. */
  abraDir: () => string;
  detectTailscale: () => Promise<string | null>;
  /** Live listener state from a running abra-agent; null when no agent answers. */
  agentInboxStatus: () => Promise<AgentInboxStatusBody | null>;
  /** Override remote-unlock HTTPS (tests / lease revoke on unpair). */
  remoteRequest?: RemoteHttpsJsonFn;
  error?: (line: string) => void;
}

export async function ttyConfirm(question: string): Promise<boolean> {
  const answer = await promptTtyLine(question);
  return /^y(es)?$/i.test(answer.trim());
}

export function defaultSyncDeps(): SyncDeps {
  return {
    abraDir: () => abraDir(),
    detectTailscale: () => detectTailscaleIPv4(),
    agentInboxStatus: async () => {
      if (!shouldTryAgent()) return null;
      try {
        return await agentInboxStatus();
      } catch {
        return null;
      }
    },
    authenticate: (reason) => authenticate(reason),
    loadVault,
    updateVault: (mutator) => updateVault(mutator),
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
  let created = false;
  const vault = await deps.updateVault((fresh) => {
    const r = getOrCreateSyncIdentity(fresh, { now: deps.now() });
    created = r.created;
    return r.created ? r.vault : VAULT_UNCHANGED;
  });
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

  // Capture before delete — unlockWrap + address needed for lease revoke push.
  const wrapBefore = found.peer.unlockWrap;
  const hostBefore = found.peer.lastAddress;
  const peerSyncId = found.id;
  const peerNameBefore = found.peer.name;
  const hubIdentity = before.syncIdentity;

  let removed!: ReturnType<typeof removePeer>["removed"];
  const vault = await deps.updateVault((fresh) => {
    const r = removePeer(fresh, found.id);
    removed = r.removed;
    return r.vault;
  });
  refreshInboxAnchors(vault, deps);

  // Bot leases for this peer: best-effort revoke after vault write (no lock held).
  if (isRemoteUnlockEnabled() && (wrapBefore || hubIdentity)) {
    await revokePeerLeasesBestEffort({
      vault: { ...vault, syncIdentity: vault.syncIdentity ?? hubIdentity },
      peerName: peerNameBefore,
      peerSyncId,
      unlockWrap: wrapBefore,
      host: hostBefore,
      base: deps.abraDir(),
      now: deps.now,
      request: deps.remoteRequest,
      log: (line) => deps.log(green(`✓ ${line}`)),
      error: deps.error ?? ((line) => deps.log(yellow(`⚠ ${line}`))),
    });
  }

  deps.log(green(`✓ unpaired "${removed.peer.name}" (${removed.peer.idFingerprint})`));
}

/** Keep the inbox's public-key mirror in step after peer/inbox changes (no-op if never enabled). */
function refreshInboxAnchors(vault: Vault, deps: SyncDeps): void {
  if (vault.syncInbox) syncAnchorsFromVault(deps.abraDir(), vault);
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
      yellow(
        `⚠ the peer did not acknowledge its save (${result.peerSaveError ?? "no acknowledgement"}) — it may not have saved; run abra sync peers on both machines`,
      ),
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
    refreshInboxAnchors(await deps.loadVault(), deps);
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
  refreshInboxAnchors(await deps.loadVault(), deps);
  return result;
}

// ───────────────────────────── accept policy ─────────────────────────────

export interface SyncAcceptCliOptions {
  from?: string;
  projects?: string;
  auto?: boolean;
  remove?: boolean;
  list?: boolean;
  json?: boolean;
}

function printAcceptRules(vault: Vault, deps: SyncDeps, json?: boolean): void {
  const rules = vault.syncAccept ?? [];
  if (json) {
    deps.log(
      JSON.stringify(
        rules.map((r) => ({
          from: r.from,
          fromName: r.from === "*" ? null : vault.syncPeers?.[r.from]?.name ?? null,
          projects: r.projects,
          auto: r.auto,
        })),
        null,
        2,
      ),
    );
    return;
  }
  if (rules.length === 0) {
    deps.log(dim("No accept rules — every inbound bundle is queued for: abra sync inbox --apply <id>"));
    return;
  }
  for (const r of rules) deps.log(`  ${describeAcceptRule(vault, r)}`);
  deps.log(dim("Unmatched bundles are queued. A matching queue rule beats a matching auto rule."));
}

/** Resolve --from to a paired SOURCE peer id ("*" when absent). */
function resolveAcceptFrom(vault: Vault, from: string | undefined): string {
  if (from === undefined) return "*";
  const found = findPeer(vault, from);
  if (!found) throw new Error(`no paired peer named "${from}" — see: abra sync peers`);
  if (found.peer.role !== "source") {
    throw new Error(`peer "${found.peer.name}" is a receiver for this machine — accept rules only apply to sources`);
  }
  return found.id;
}

export async function cmdSyncAccept(opts: SyncAcceptCliOptions, deps: SyncDeps = defaultSyncDeps()): Promise<void> {
  const changing = opts.from !== undefined || opts.projects !== undefined || opts.auto || opts.remove;
  if (opts.list || !changing) {
    if (opts.list && changing) throw new Error("--list cannot be combined with other options");
    printAcceptRules(await deps.loadVault(), deps, opts.json);
    return;
  }
  if (opts.remove && opts.auto) throw new Error("--remove and --auto cannot be combined");
  const projects = parseProjectsOption(opts.projects);
  resolveAcceptFrom(await deps.loadVault(), opts.from);

  await deps.authenticate("abracadabra: change the sync accept policy");
  if (opts.remove) {
    let removed = 0;
    await deps.updateVault((fresh) => {
      const from = resolveAcceptFrom(fresh, opts.from);
      const r = removeAcceptRules(fresh, { from, projects });
      if (r.removed === 0) throw new Error("no accept rule with that --from / -p selector — see: abra sync accept --list");
      removed = r.removed;
      return r.vault;
    });
    deps.log(green(`✓ removed ${removed} accept rule${removed === 1 ? "" : "s"}`));
    return;
  }
  let rule!: SyncAcceptRule;
  let action!: ReturnType<typeof upsertAcceptRule>["action"];
  const vault = await deps.updateVault((fresh) => {
    rule = { from: resolveAcceptFrom(fresh, opts.from), projects, auto: opts.auto === true };
    const r = upsertAcceptRule(fresh, rule);
    action = r.action;
    return r.vault;
  });
  deps.log(green(`✓ ${action} rule: ${describeAcceptRule(vault, rule)}`));
}

// ───────────────────────────── inbox ─────────────────────────────

export interface SyncInboxCliOptions {
  json?: boolean;
  apply?: string;
  reject?: string;
  status?: boolean;
  enable?: boolean;
  disable?: boolean;
  bind?: string;
  port?: string;
}

interface QueuedListItem {
  bundleId: string;
  from: string | null;
  fromName: string | null;
  projects: string[];
  createdAt: number | null;
  receivedAt: number | null;
  verified: boolean;
  reason?: string;
}

function listQueue(vault: Vault, queue: InboxQueue): QueuedListItem[] {
  const trust = trustFromVault(vault);
  return queue.ids().map((id) => {
    try {
      const entry = queue.read(id);
      const env = entry.envelope;
      const item: QueuedListItem = {
        bundleId: env.bundleId,
        from: env.from,
        fromName: vault.syncPeers?.[env.from]?.name ?? null,
        projects: env.projects,
        createdAt: env.createdAt,
        receivedAt: entry.receivedAt,
        verified: false,
      };
      try {
        if (!trust) throw new EnvelopeError("wrong-recipient", "this vault has no sync identity");
        verifyEnvelope(env, trust);
        item.verified = true;
      } catch (err) {
        item.reason = err instanceof EnvelopeError ? err.reason : "invalid";
      }
      return item;
    } catch {
      return { bundleId: id, from: null, fromName: null, projects: [], createdAt: null, receivedAt: null, verified: false, reason: "unreadable" };
    }
  });
}

function resolveTargets(queue: InboxQueue, target: string): string[] {
  if (target === "all") return queue.ids();
  if (!isUuid(target)) throw new Error(`invalid bundle id "${target}" — use an id from: abra sync inbox`);
  if (!queue.has(target)) throw new Error(`no queued bundle ${target} — see: abra sync inbox`);
  return [target.toLowerCase()];
}

async function inboxApply(target: string, deps: SyncDeps): Promise<void> {
  const base = deps.abraDir();
  const queue = new InboxQueue(base);
  const ids = resolveTargets(queue, target);
  if (ids.length === 0) {
    deps.log(dim("Inbox empty — nothing to apply"));
    return;
  }
  await deps.authenticate(`abracadabra: apply ${ids.length} queued sync bundle${ids.length === 1 ? "" : "s"} to this vault`);
  const applied: { id: string; createdAt: number; result: ApplyResult }[] = [];
  const failed: { id: string; why: string }[] = [];
  await deps.updateVault((fresh) => {
    let vault = fresh;
    let changed = false;
    for (const id of ids) {
      try {
        const { envelope } = queue.read(id);
        const result = applyEnvelope(vault, envelope);
        vault = result.vault;
        changed ||= result.changed;
        applied.push({ id, createdAt: envelope.createdAt, result });
      } catch (err) {
        failed.push({ id, why: err instanceof EnvelopeError ? err.reason : "unreadable" });
      }
    }
    return changed ? vault : VAULT_UNCHANGED;
  });
  const seen = new ReplayCache(base);
  for (const a of applied) {
    queue.remove(a.id);
    seen.add(a.id, a.createdAt, deps.now());
    deps.log(green(`✓ applied ${a.id} from "${a.result.peerName}"`));
    for (const c of a.result.counts) deps.log(`  ${formatCounts(c)}`);
  }
  if (applied.some((a) => a.result.counts.some((c) => c.keptLocal > 0))) {
    deps.log(dim("  kept local = this machine's value differed and was kept (receiver wins)"));
  }
  for (const f of failed) deps.log(red(`✗ ${f.id}: ${f.why} — left queued (remove with: abra sync inbox --reject ${f.id})`));
  if (failed.length > 0) throw new Error(`${failed.length} bundle${failed.length === 1 ? "" : "s"} could not be applied`);
}

function inboxReject(target: string, deps: SyncDeps): void {
  const base = deps.abraDir();
  const queue = new InboxQueue(base);
  const ids = resolveTargets(queue, target);
  const seen = new ReplayCache(base);
  for (const id of ids) {
    try {
      seen.add(id, queue.read(id).envelope.createdAt, deps.now());
    } catch {
      /* unreadable file — just delete it */
    }
    queue.remove(id);
    deps.log(green(`✓ rejected ${id}`));
  }
  if (ids.length === 0) deps.log(dim("Inbox empty — nothing to reject"));
}

function parseInboxPort(raw: string | undefined): number {
  if (raw === undefined) return INBOX_DEFAULT_PORT;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid --port ${raw}`);
  return port;
}

async function inboxEnable(opts: SyncInboxCliOptions, deps: SyncDeps): Promise<void> {
  const port = parseInboxPort(opts.port);
  let bindNote: string;
  if (opts.bind !== undefined) {
    if (net.isIP(opts.bind) === 0) throw new Error(`--bind must be an IP address (got "${opts.bind}")`);
    bindNote = opts.bind;
  } else {
    const ts = await deps.detectTailscale();
    if (!ts) {
      throw new Error("Tailscale IPv4 not found (is Tailscale running?) — pass --bind <ip> to choose the listen address explicitly");
    }
    bindNote = `${ts} (Tailscale, re-detected when the listener starts)`;
  }
  await deps.authenticate("abracadabra: enable the sync inbox");
  const vault = await deps.updateVault((fresh) => ({
    ...fresh,
    syncInbox: { enabled: true, port, ...(opts.bind !== undefined ? { bind: opts.bind } : {}) },
  }));
  syncAnchorsFromVault(deps.abraDir(), vault);
  deps.log(green("✓ sync inbox enabled"));
  deps.log(`  listen:  ${bindNote}:${port}`);
  if (opts.bind === "0.0.0.0" || opts.bind === "::") {
    deps.log(yellow("⚠ listening on every interface — prefer your Tailscale IP"));
  }
  const sources = Object.values(vault.syncPeers ?? {}).filter((p) => p.role === "source").length;
  if (sources === 0) deps.log(yellow("⚠ no source peers paired yet — the listener stays off until you pair one"));
  deps.log(dim("The inbox runs inside abra-agent (abra agent); check with: abra sync inbox --status"));
}

async function inboxDisable(deps: SyncDeps): Promise<void> {
  await deps.authenticate("abracadabra: disable the sync inbox");
  const vault = await deps.updateVault((fresh) => ({
    ...fresh,
    syncInbox: { ...(fresh.syncInbox ?? { port: INBOX_DEFAULT_PORT }), enabled: false },
  }));
  syncAnchorsFromVault(deps.abraDir(), vault);
  deps.log(green("✓ sync inbox disabled"));
}

async function inboxStatus(opts: SyncInboxCliOptions, deps: SyncDeps): Promise<void> {
  const vault = await deps.loadVault();
  const s = vault.syncInbox;
  const agent = await deps.agentInboxStatus();
  const status = {
    enabled: s?.enabled === true,
    bind: s?.bind ?? (s ? "tailscale" : null),
    port: s?.port ?? null,
    sources: Object.values(vault.syncPeers ?? {}).filter((p) => p.role === "source").length,
    queued: new InboxQueue(deps.abraDir()).ids().length,
    agent: agent !== null,
    listening: agent?.listening ?? false,
    listeningOn: agent?.listening ? `${agent.bind}:${agent.port}` : null,
    error: agent?.error ?? null,
  };
  if (opts.json) {
    deps.log(JSON.stringify(status, null, 2));
    return;
  }
  deps.log(`enabled:    ${status.enabled ? green("yes") : "no"}`);
  deps.log(`bind:       ${status.bind ?? "-"}`);
  deps.log(`port:       ${status.port ?? "-"}`);
  deps.log(`sources:    ${status.sources}`);
  deps.log(`queued:     ${status.queued}`);
  deps.log(
    `listening:  ${
      status.listening ? green(`yes (${status.listeningOn})`) : status.agent ? "no" : "no (abra-agent not reachable)"
    }`,
  );
  if (status.error) deps.log(yellow(`⚠ ${status.error}`));
}

export async function cmdSyncInbox(opts: SyncInboxCliOptions, deps: SyncDeps = defaultSyncDeps()): Promise<void> {
  const modes = [opts.apply !== undefined, opts.reject !== undefined, opts.status, opts.enable, opts.disable].filter(Boolean);
  if (modes.length > 1) throw new Error("pass only one of --apply, --reject, --status, --enable, --disable");
  if ((opts.bind !== undefined || opts.port !== undefined) && !opts.enable) {
    throw new Error("--bind/--port only apply with --enable");
  }
  if (opts.apply !== undefined) return inboxApply(opts.apply, deps);
  if (opts.reject !== undefined) return inboxReject(opts.reject, deps);
  if (opts.enable) return inboxEnable(opts, deps);
  if (opts.disable) return inboxDisable(deps);
  if (opts.status) return inboxStatus(opts, deps);

  const queue = new InboxQueue(deps.abraDir());
  const items = queue.ids().length === 0 ? [] : listQueue(await deps.loadVault(), queue);
  if (opts.json) {
    deps.log(JSON.stringify(items, null, 2));
    return;
  }
  if (items.length === 0) {
    deps.log(dim("Inbox empty"));
    return;
  }
  for (const it of items) {
    const mark = it.verified ? green("✓ verified") : red(`✗ ${it.reason ?? "unverified"}`);
    deps.log(`${bold(it.bundleId)}  from ${it.fromName ?? it.from ?? "?"}  ${mark}`);
    deps.log(
      dim(`  projects ${it.projects.join(", ") || "-"} · created ${it.createdAt ? new Date(it.createdAt).toLocaleString() : "?"}`),
    );
  }
  deps.log(dim("Apply with: abra sync inbox --apply <id|all>   ·   drop with: abra sync inbox --reject <id|all>"));
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

  sync
    .command("accept")
    .description("Set which inbound bundles auto-apply (default: everything is queued); no options = list rules")
    .option("--from <peer>", "paired source peer name/id (default: all sources)")
    .option("-p, --projects <list>", "comma-separated project names (default: all projects)")
    .option("--auto", "apply matching bundles automatically while abra-agent is unlocked")
    .option("--remove", "remove the rule with this --from / -p selector")
    .option("--list", "list rules")
    .option("--json", "JSON output (with --list)")
    .action(async (opts: SyncAcceptCliOptions) => {
      try {
        await cmdSyncAccept(opts);
      } catch (err) {
        fail(err);
      }
    });

  sync
    .command("inbox")
    .description("List queued inbound bundles; --apply/--reject them; --enable/--disable/--status the agent listener")
    .option("--json", "JSON output (list / --status)")
    .option("--apply <id>", "verify, decrypt and merge a queued bundle (or 'all'); local values win conflicts")
    .option("--reject <id>", "delete a queued bundle (or 'all')")
    .option("--status", "show enabled / bind / port / listening")
    .option("--enable", "run the inbox listener in abra-agent")
    .option("--disable", "stop the inbox listener")
    .option("--bind <ip>", "listen address with --enable (default: this machine's Tailscale IPv4)")
    .option("--port <number>", `listen port with --enable (default ${INBOX_DEFAULT_PORT})`)
    .action(async (opts: SyncInboxCliOptions) => {
      try {
        await cmdSyncInbox(opts);
      } catch (err) {
        fail(err);
      }
    });
}
