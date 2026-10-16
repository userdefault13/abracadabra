import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { loadVault, type Vault, type VaultMutator, type VarEntry } from "../core/vault.js";
import { abraDir } from "../core/paths.js";
import { authenticate } from "../platform/index.js";
import { LeaseStore } from "../agent/lease-store.js";
import { findPeer } from "../sync/peers.js";
import { appendAuditLog } from "../remote/audit.js";
import { isRemoteUnlockEnabled } from "../remote/feature.js";
import {
  remoteLeasePushViaHttp,
  remoteLeaseRevokeViaHttp,
  type RemoteHttpsJsonFn,
} from "../remote/hub-client.js";
import {
  getHubLeaseRecord,
  listHubLeaseRecords,
  listHubLeasesNeedingRenew,
  putHubLeaseRecord,
  deleteHubLeaseRecord,
  type HubLeaseRecord,
} from "../remote/hub-leases.js";
import {
  LEASE_DEFAULT_TTL_SECONDS,
  LEASE_HUB_HARD_MAX_TTL_SECONDS,
  LeaseError,
  parseLeaseTtl,
  sealLease,
  type LeaseBinding,
} from "../remote/lease.js";
import { listEnrolledPeers, selectEnrolledPeers, type EnrolledPeer } from "../remote/peers.js";
import { REMOTE_UNLOCK_PORT } from "../remote/wire.js";

/**
 * Bot lease CLI (PR 7 / Phase 2).
 * Feature off by default — require ABRA_REMOTE_UNLOCK=1.
 *
 * Binding safety: `--bin` takes exe+dev+ino as resolved on the *receiver*.
 * Operators run `abra lease bind-info <path>` on the receiver (prints non-secret
 * identity), then pass that JSON (file or inline) to hub `grant`. The hub never
 * resolves a receiver filesystem path itself (inode/dev would be wrong).
 */

const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

export interface LeaseCliDeps {
  authenticate: (reason: string) => Promise<void>;
  loadVault: () => Promise<Vault>;
  updateVault?: (mutator: VaultMutator) => Promise<Vault>;
  now?: () => number;
  log?: (line: string) => void;
  error?: (line: string) => void;
  base?: () => string;
  audit?: typeof appendAuditLog;
  request?: RemoteHttpsJsonFn;
}

export function defaultLeaseCliDeps(): LeaseCliDeps {
  return {
    authenticate: (reason) => authenticate(reason),
    loadVault,
    now: () => Date.now(),
    log: (line) => console.log(green(`✓ ${line}`)),
    error: (line) => console.error(red(`✗ ${line}`)),
    base: () => abraDir(),
    audit: appendAuditLog,
  };
}

function requireFlag(): void {
  if (!isRemoteUnlockEnabled()) {
    throw new Error("remote unlock is disabled — set ABRA_REMOTE_UNLOCK=1 to enable");
  }
}

function peerCa(peer: EnrolledPeer): string {
  const ca = peer.unlockWrap.listenerCert;
  if (!ca) {
    throw new Error(
      `peer "${peer.name}" has no stored listener cert — re-enroll: abra remote enroll ${peer.name}`,
    );
  }
  return ca;
}

function requireHubIdentity(vault: Vault) {
  const id = vault.syncIdentity;
  if (!id) throw new Error("this vault has no sync identity — pair first (abra sync pair)");
  return id;
}

/**
 * Parse `--bin`: bind-info JSON file path, inline JSON, or `exe@dev:ino`.
 * Never accepts a bare receiver binary path (hub cannot resolve remote inodes).
 */
export function parseLeaseBinSpec(raw: string): LeaseBinding {
  const s = raw.trim();
  if (!s) throw new Error("--bin is required (receiver bind-info JSON or exe@dev:ino)");

  // Inline JSON
  if (s.startsWith("{")) {
    let obj: unknown;
    try {
      obj = JSON.parse(s);
    } catch {
      throw new Error("--bin inline JSON is malformed");
    }
    return bindingFromUnknown(obj);
  }

  // exe@dev:ino
  const at = s.match(/^(.+)@(\d+):(\d+)$/);
  if (at) {
    return {
      exe: at[1]!,
      dev: Number(at[2]),
      ino: Number(at[3]),
    };
  }

  // Path to bind-info JSON file (local to hub — operator copied it)
  const file = path.resolve(s);
  if (!fs.existsSync(file)) {
    throw new Error(
      `--bin must be receiver bind-info JSON (file or inline) or exe@dev:ino — ` +
        `run on the receiver: abra lease bind-info <path> --json`,
    );
  }
  let obj: unknown;
  try {
    obj = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Error(`--bin file is not valid JSON: ${file}`);
  }
  return bindingFromUnknown(obj);
}

function bindingFromUnknown(raw: unknown): LeaseBinding {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("bind-info must be an object with exe, dev, ino");
  }
  const o = raw as Record<string, unknown>;
  if (typeof o.exe !== "string" || !o.exe) {
    throw new Error("bind-info.exe must be a non-empty string");
  }
  if (typeof o.dev !== "number" || !Number.isFinite(o.dev)) {
    throw new Error("bind-info.dev must be a number");
  }
  if (typeof o.ino !== "number" || !Number.isFinite(o.ino)) {
    throw new Error("bind-info.ino must be a number");
  }
  return { exe: o.exe, dev: o.dev, ino: o.ino };
}

/** Receiver: resolve a local path to GrantCaller identity (non-secret). */
export function cmdLeaseBindInfo(
  binPath: string,
  opts: { json?: boolean } = {},
): LeaseBinding {
  requireFlag();
  let exe: string;
  try {
    exe = fs.realpathSync(path.resolve(binPath));
  } catch {
    throw new Error(`path not found: ${binPath}`);
  }
  let st: fs.Stats;
  try {
    st = fs.statSync(exe);
  } catch {
    throw new Error(`path not readable: ${exe}`);
  }
  if (!st.isFile()) throw new Error(`path must be a regular file: ${exe}`);
  const binding: LeaseBinding = { exe, dev: st.dev, ino: st.ino };
  if (opts.json) {
    console.log(JSON.stringify(binding));
  } else {
    console.log(`exe=${binding.exe}`);
    console.log(`dev=${binding.dev}`);
    console.log(`ino=${binding.ino}`);
    console.log(dim("Copy this to the hub as --bin (JSON file or exe@dev:ino). Non-secret."));
  }
  return binding;
}

function copyProjectVars(vault: Vault, project: string): Record<string, VarEntry> {
  const p = vault.projects[project];
  if (!p) throw new Error(`project not found: ${project}`);
  const vars: Record<string, VarEntry> = {};
  for (const [k, e] of Object.entries(p.vars)) {
    vars[k] = { value: e.value, secret: e.secret, updatedAt: e.updatedAt };
  }
  return vars;
}

/** Zero string values after seal (best-effort; JS strings are immutable copies). */
function scrubVars(vars: Record<string, VarEntry>): void {
  for (const e of Object.values(vars)) {
    if (typeof e.value === "string" && e.value.length > 0) {
      (e as { value: string }).value = "";
    }
  }
}

export interface LeaseGrantOpts {
  peer: string;
  bin: string;
  ttl?: string;
}

export async function cmdLeaseGrant(
  project: string,
  opts: LeaseGrantOpts,
  deps: LeaseCliDeps = defaultLeaseCliDeps(),
): Promise<{ leaseId: string; expiresAt: number }> {
  requireFlag();
  const projectName = project.trim();
  if (!projectName) throw new Error("project is required");
  if (!opts.peer?.trim()) throw new Error("--peer is required");
  if (!opts.bin?.trim()) throw new Error("--bin is required");

  const ttlSeconds = opts.ttl
    ? parseLeaseTtl(opts.ttl)
    : LEASE_DEFAULT_TTL_SECONDS;
  if (ttlSeconds > LEASE_HUB_HARD_MAX_TTL_SECONDS) {
    throw new LeaseError(
      "ttl-exceeded",
      `lease ttl must be at most ${LEASE_HUB_HARD_MAX_TTL_SECONDS / 86400}d`,
    );
  }

  const binding = parseLeaseBinSpec(opts.bin);
  const base = deps.base?.() ?? abraDir();

  // Touch ID before reading project secrets (never hold vault lock across auth/network).
  await deps.authenticate(
    `abracadabra: grant bot lease for "${projectName}" to peer ${opts.peer.trim()}`,
  );

  const vault = await deps.loadVault();
  const hub = requireHubIdentity(vault);
  const selected = selectEnrolledPeers(vault, { peers: opts.peer.trim() });
  if (selected.length !== 1) {
    throw new Error(`expected one enrolled peer for "${opts.peer}" — enroll first`);
  }
  const peer = selected[0]!;
  if (!peer.host) {
    throw new Error(
      `peer "${peer.name}" has no lastAddress — re-pair before lease grant`,
    );
  }

  const vars = copyProjectVars(vault, projectName);
  const issuedAt = (deps.now ?? Date.now)();
  let lease;
  try {
    lease = sealLease({
      hub,
      peer: {
        id: peer.unlockWrap.deviceId,
        x25519: peer.unlockWrap.deviceX25519,
      },
      project: projectName,
      binding,
      vars,
      ttlSeconds,
      issuedAt,
      maxTtlSeconds: LEASE_HUB_HARD_MAX_TTL_SECONDS,
    });
  } finally {
    scrubVars(vars);
  }

  const push = await remoteLeasePushViaHttp({
    host: peer.host,
    port: REMOTE_UNLOCK_PORT,
    ca: peerCa(peer),
    lease,
    request: deps.request,
  });

  if (!push.ok) {
    (deps.audit ?? appendAuditLog)(
      { op: "lease-grant", peer: peer.name, result: push.reason },
      { base, now: deps.now },
    );
    throw new Error(
      push.reason === "unreachable"
        ? `peer "${peer.name}" unreachable for lease grant`
        : `lease grant to "${peer.name}" failed: ${push.reason}`,
    );
  }

  const record: HubLeaseRecord = {
    v: 1,
    leaseId: lease.leaseId,
    peerName: peer.name,
    peerSyncId: peer.id,
    peerDeviceId: peer.unlockWrap.deviceId,
    project: projectName,
    binding,
    issuedAt: lease.issuedAt,
    expiresAt: lease.expiresAt,
    ttlSeconds,
  };
  putHubLeaseRecord(record, base);

  (deps.audit ?? appendAuditLog)(
    { op: "lease-grant", peer: peer.name, result: "ok" },
    { base, now: deps.now },
  );
  deps.log?.(
    `granted lease ${lease.leaseId} project=${projectName} peer=${peer.name} expires=${new Date(lease.expiresAt).toLocaleString()}`,
  );
  return { leaseId: lease.leaseId, expiresAt: lease.expiresAt };
}

export function cmdLeaseList(deps: LeaseCliDeps = defaultLeaseCliDeps()): {
  hub: HubLeaseRecord[];
  receiver: ReturnType<LeaseStore["listPublic"]>;
} {
  requireFlag();
  const base = deps.base?.() ?? abraDir();
  const hub = listHubLeaseRecords(base);
  const receiver = new LeaseStore({ base, now: deps.now }).listPublic();

  if (hub.length === 0 && receiver.length === 0) {
    console.log(dim("(no leases)"));
  }
  for (const r of hub) {
    console.log(
      `hub  ${r.leaseId}  project=${r.project}  peer=${r.peerName}  expires=${new Date(r.expiresAt).toLocaleString()}`,
    );
    console.log(dim(`     binding=${r.binding.exe} dev=${r.binding.dev} ino=${r.binding.ino}`));
  }
  for (const r of receiver) {
    console.log(
      `recv ${r.leaseId}  project=${r.project}  expires=${new Date(r.expiresAt).toLocaleString()}`,
    );
    console.log(dim(`     binding=${r.binding.exe} dev=${r.binding.dev} ino=${r.binding.ino}`));
  }
  return { hub, receiver };
}

export interface LeaseRevokeCliOpts {
  peer?: string;
}

export async function cmdLeaseRevoke(
  leaseIdOrUndefined: string | undefined,
  opts: LeaseRevokeCliOpts,
  deps: LeaseCliDeps = defaultLeaseCliDeps(),
): Promise<void> {
  requireFlag();
  const base = deps.base?.() ?? abraDir();
  const leaseId = leaseIdOrUndefined?.trim();
  const peerOpt = opts.peer?.trim();

  if (Boolean(leaseId) === Boolean(peerOpt)) {
    throw new Error("usage: abra lease revoke <leaseId> | abra lease revoke --peer <name>");
  }

  await deps.authenticate(
    leaseId
      ? `abracadabra: revoke bot lease ${leaseId}`
      : `abracadabra: revoke bot leases for peer ${peerOpt}`,
  );

  const vault = await deps.loadVault();
  const hub = requireHubIdentity(vault);

  if (leaseId) {
    const rec = getHubLeaseRecord(leaseId, base);
    if (!rec) throw new Error(`no hub lease record for ${leaseId}`);
    const enrolled = listEnrolledPeers(vault).find(
      (p) => p.unlockWrap.deviceId === rec.peerDeviceId || p.name === rec.peerName,
    );
    if (!enrolled?.host || !enrolled.unlockWrap.listenerCert) {
      deleteHubLeaseRecord(leaseId, base);
      deps.error?.(
        `peer "${rec.peerName}" unreachable for lease revoke — hub record cleared; lease will lapse at expiry`,
      );
      (deps.audit ?? appendAuditLog)(
        { op: "lease-revoke", peer: rec.peerName, result: "unreachable" },
        { base, now: deps.now },
      );
      return;
    }
    const out = await remoteLeaseRevokeViaHttp({
      host: enrolled.host,
      port: REMOTE_UNLOCK_PORT,
      ca: peerCa(enrolled),
      hubIdentity: hub,
      peerDeviceId: rec.peerDeviceId,
      leaseId,
      now: deps.now,
      request: deps.request,
    });
    deleteHubLeaseRecord(leaseId, base);
    if (!out.ok) {
      (deps.audit ?? appendAuditLog)(
        { op: "lease-revoke", peer: rec.peerName, result: out.reason },
        { base, now: deps.now },
      );
      if (out.reason === "unreachable") {
        deps.error?.(
          `peer "${rec.peerName}" unreachable — hub record cleared; lease will lapse at expiry`,
        );
        return;
      }
      throw new Error(`lease revoke failed: ${out.reason}`);
    }
    (deps.audit ?? appendAuditLog)(
      { op: "lease-revoke", peer: rec.peerName, result: "ok" },
      { base, now: deps.now },
    );
    deps.log?.(`revoked lease ${leaseId} on "${rec.peerName}"`);
    return;
  }

  // --peer: revoke all for that peer
  const found = findPeer(vault, peerOpt!);
  if (!found) throw new Error(`no paired peer named "${peerOpt}" — see: abra sync peers`);
  const enrolled = listEnrolledPeers(vault).find(
    (p) => p.id === found.id || p.name === found.peer.name,
  );
  const deviceId =
    enrolled?.unlockWrap.deviceId ??
    listHubLeaseRecords(base).find(
      (r) => r.peerSyncId === found.id || r.peerName === found.peer.name,
    )?.peerDeviceId;

  if (!deviceId) {
    throw new Error(`no leases / enrollment for peer "${found.peer.name}"`);
  }

  if (!enrolled?.host || !enrolled.unlockWrap.listenerCert) {
    const n = listHubLeaseRecords(base).filter(
      (r) => r.peerSyncId === found.id || r.peerName === found.peer.name,
    ).length;
    for (const r of listHubLeaseRecords(base)) {
      if (r.peerSyncId === found.id || r.peerName === found.peer.name) {
        deleteHubLeaseRecord(r.leaseId, base);
      }
    }
    deps.error?.(
      `peer "${found.peer.name}" unreachable for lease revoke — cleared ${n} hub record(s); leases will lapse at expiry`,
    );
    (deps.audit ?? appendAuditLog)(
      { op: "lease-revoke", peer: found.peer.name, result: "unreachable" },
      { base, now: deps.now },
    );
    return;
  }

  const out = await remoteLeaseRevokeViaHttp({
    host: enrolled.host,
    port: REMOTE_UNLOCK_PORT,
    ca: peerCa(enrolled),
    hubIdentity: hub,
    peerDeviceId: deviceId,
    all: true,
    now: deps.now,
    request: deps.request,
  });
  for (const r of listHubLeaseRecords(base)) {
    if (
      r.peerSyncId === found.id ||
      r.peerName === found.peer.name ||
      r.peerDeviceId === deviceId
    ) {
      deleteHubLeaseRecord(r.leaseId, base);
    }
  }
  if (!out.ok) {
    (deps.audit ?? appendAuditLog)(
      { op: "lease-revoke", peer: found.peer.name, result: out.reason },
      { base, now: deps.now },
    );
    if (out.reason === "unreachable") {
      deps.error?.(
        `peer "${found.peer.name}" unreachable — hub records cleared; leases will lapse at expiry`,
      );
      return;
    }
    throw new Error(`lease revoke failed: ${out.reason}`);
  }
  (deps.audit ?? appendAuditLog)(
    { op: "lease-revoke", peer: found.peer.name, result: "ok" },
    { base, now: deps.now },
  );
  deps.log?.(
    `revoked ${out.removed} lease(s) on "${found.peer.name}"`,
  );
}

export interface LeaseRenewOpts {
  all?: boolean;
}

export async function cmdLeaseRenew(
  opts: LeaseRenewOpts = {},
  deps: LeaseCliDeps = defaultLeaseCliDeps(),
): Promise<{ renewed: number; failed: number }> {
  requireFlag();
  const base = deps.base?.() ?? abraDir();
  const now = (deps.now ?? Date.now)();
  const candidates = opts.all
    ? listHubLeaseRecords(base)
    : listHubLeasesNeedingRenew(base, { now });

  if (candidates.length === 0) {
    deps.log?.("no leases need renew");
    return { renewed: 0, failed: 0 };
  }

  // One Touch ID for the whole renew run (no silent background loop).
  await deps.authenticate(
    `abracadabra: renew ${candidates.length} bot lease(s)`,
  );

  const vault = await deps.loadVault();
  const hub = requireHubIdentity(vault);
  let renewed = 0;
  let failed = 0;

  for (const rec of candidates) {
    const enrolled = listEnrolledPeers(vault).find(
      (p) =>
        p.unlockWrap.deviceId === rec.peerDeviceId ||
        p.id === rec.peerSyncId ||
        p.name === rec.peerName,
    );
    if (!enrolled?.host || !enrolled.unlockWrap.listenerCert) {
      deps.error?.(`skip ${rec.leaseId}: peer "${rec.peerName}" not reachable`);
      failed++;
      continue;
    }

    let vars: Record<string, VarEntry> = {};
    try {
      vars = copyProjectVars(vault, rec.project);
    } catch (err) {
      deps.error?.(
        `skip ${rec.leaseId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      failed++;
      continue;
    }

    const issuedAt = (deps.now ?? Date.now)();
    let lease;
    try {
      lease = sealLease({
        hub,
        peer: {
          id: enrolled.unlockWrap.deviceId,
          x25519: enrolled.unlockWrap.deviceX25519,
        },
        project: rec.project,
        binding: rec.binding,
        vars,
        ttlSeconds: Math.min(rec.ttlSeconds, LEASE_HUB_HARD_MAX_TTL_SECONDS),
        issuedAt,
        maxTtlSeconds: LEASE_HUB_HARD_MAX_TTL_SECONDS,
      });
    } catch (err) {
      scrubVars(vars);
      deps.error?.(
        `skip ${rec.leaseId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      failed++;
      continue;
    } finally {
      scrubVars(vars);
    }

    const push = await remoteLeasePushViaHttp({
      host: enrolled.host,
      port: REMOTE_UNLOCK_PORT,
      ca: peerCa(enrolled),
      lease,
      request: deps.request,
    });
    if (!push.ok) {
      (deps.audit ?? appendAuditLog)(
        { op: "lease-renew", peer: rec.peerName, result: push.reason },
        { base, now: deps.now },
      );
      deps.error?.(
        push.reason === "unreachable"
          ? `peer "${rec.peerName}" unreachable for renew of ${rec.leaseId}`
          : `renew ${rec.leaseId} failed: ${push.reason}`,
      );
      failed++;
      continue;
    }

    deleteHubLeaseRecord(rec.leaseId, base);
    putHubLeaseRecord(
      {
        v: 1,
        leaseId: lease.leaseId,
        peerName: rec.peerName,
        peerSyncId: rec.peerSyncId,
        peerDeviceId: enrolled.unlockWrap.deviceId,
        project: rec.project,
        binding: rec.binding,
        issuedAt: lease.issuedAt,
        expiresAt: lease.expiresAt,
        ttlSeconds: Math.min(rec.ttlSeconds, LEASE_HUB_HARD_MAX_TTL_SECONDS),
      },
      base,
    );
    (deps.audit ?? appendAuditLog)(
      { op: "lease-renew", peer: rec.peerName, result: "ok" },
      { base, now: deps.now },
    );
    deps.log?.(
      `renewed ${rec.leaseId} → ${lease.leaseId} expires=${new Date(lease.expiresAt).toLocaleString()}`,
    );
    renewed++;
  }

  return { renewed, failed };
}

function fail(err: unknown): never {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(red(`✗ ${msg}`));
  process.exit(1);
}

export function registerLeaseCommands(program: Command): void {
  const lease = program
    .command("lease")
    .description(
      "Scoped bot leases from the hub (requires ABRA_REMOTE_UNLOCK=1; default TTL 7d)",
    );

  lease
    .command("bind-info <path>")
    .description(
      "Receiver: print exe+dev+ino for a local binary (non-secret; pass to hub --bin)",
    )
    .option("--json", "print JSON only")
    .action((binPath: string, opts: { json?: boolean }) => {
      try {
        cmdLeaseBindInfo(binPath, opts);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  lease
    .command("grant <project>")
    .description(
      "Hub: Touch ID, seal project to peer device key, push lease (default TTL 7d, max 7d)",
    )
    .requiredOption("--peer <name>", "enrolled receiver peer name or id")
    .requiredOption(
      "--bin <spec>",
      "receiver bind-info JSON file, inline JSON, or exe@dev:ino (from abra lease bind-info)",
    )
    .option("--ttl <dur>", "lease lifetime (e.g. 7d, 24h); max 7d", "7d")
    .action(async (project: string, opts: { peer: string; bin: string; ttl?: string }) => {
      try {
        await cmdLeaseGrant(project, opts);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  lease
    .command("list")
    .description("List lease metadata on this machine (hub registry and/or receiver store)")
    .action(() => {
      try {
        cmdLeaseList();
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  lease
    .command("revoke [leaseId]")
    .description("Hub: signed revoke for one leaseId, or --peer for all of that peer")
    .option("--peer <name>", "revoke all leases for an enrolled peer")
    .action(async (leaseId: string | undefined, opts: { peer?: string }) => {
      try {
        await cmdLeaseRevoke(leaseId, opts);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  lease
    .command("renew")
    .description(
      "Hub: re-issue leases near expiry (one Touch ID per run; schedule via launchd — see docs)",
    )
    .option("--all", "renew every tracked hub lease, not only those near expiry")
    .action(async (opts: { all?: boolean }) => {
      try {
        const { failed } = await cmdLeaseRenew(opts);
        process.exit(failed > 0 ? 1 : 0);
      } catch (err) {
        fail(err);
      }
    });
}
