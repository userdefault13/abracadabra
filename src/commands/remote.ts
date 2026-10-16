import type { Command } from "commander";
import { loadVault, updateVault, type Vault, type VaultMutator } from "../core/vault.js";
import { abraDir } from "../core/paths.js";
import { authenticate } from "../platform/index.js";
import { findPeer } from "../sync/peers.js";
import { appendAuditLog } from "../remote/audit.js";
import { getOrCreatePublicDeviceKey } from "../remote/device-key.js";
import {
  clearPeerUnlockWrap,
  completeHubEnroll,
  type EnrollHubDeps,
  type EnrollOffer,
} from "../remote/enroll.js";
import { isRemoteUnlockEnabled } from "../remote/feature.js";
import { clearHubPin } from "../remote/hub-pin.js";
import {
  remoteEnrollViaHttp,
  remoteLockViaHttp,
  remoteStatusViaHttp,
  remoteUnlockViaHttp,
  type RemoteHttpsJsonFn,
} from "../remote/hub-client.js";
import { revokePeerLeasesBestEffort } from "../remote/lease-revoke-peer.js";
import { clearUnlockBlob } from "../remote/unlock-blob.js";
import { listEnrolledPeers, selectEnrolledPeers, type EnrolledPeer } from "../remote/peers.js";
import {
  buildRequestedPolicy,
  parsePolicyDuration,
} from "../remote/policy.js";
import { REMOTE_UNLOCK_PORT, type UnlockPolicy } from "../remote/wire.js";

/**
 * Remote fleet unlock CLI (PR 4/7).
 * Feature off by default — require ABRA_REMOTE_UNLOCK=1 for enroll / unlock / lock.
 * Hub offline never breaks local unlock.
 */

const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

export function cmdRemoteWhoami(opts: { base?: string } = {}): void {
  const pub = getOrCreatePublicDeviceKey({ base: opts.base ?? abraDir() });
  console.log(pub.fingerprint);
}

export interface RemoteEnrollDeps extends EnrollHubDeps {
  /**
   * Fetch a sealed enroll offer from the receiver peer.
   * Default: HTTPS over the PR 3 listener (`/v1/remote/enroll`).
   */
  fetchOffer: (
    peerNameOrId: string,
  ) => Promise<{ offer: EnrollOffer; listenerCert?: string }>;
  audit?: typeof appendAuditLog;
  base?: string;
}

export interface RemoteCliDeps {
  authenticate: (reason: string) => Promise<void>;
  loadVault: () => Promise<Vault>;
  updateVault: (mutator: VaultMutator) => Promise<Vault>;
  now?: () => number;
  log?: (line: string) => void;
  error?: (line: string) => void;
  base?: () => string;
  audit?: typeof appendAuditLog;
  /** Override HTTPS (tests / loopback). */
  request?: RemoteHttpsJsonFn;
  /**
   * How the receiver names this hub when building an enroll offer.
   * Default: hub sync identity id (receiver looks up by id).
   */
  hubNameForReceiver?: (vault: Vault) => string;
  /** After local disable — optional agent reconcile hook (tests). */
  afterDisable?: () => void | Promise<void>;
}

function defaultHubNameForReceiver(vault: Vault): string {
  const id = vault.syncIdentity?.id;
  if (!id) throw new Error("this vault has no sync identity — pair first (abra sync pair)");
  return id;
}

export function defaultRemoteCliDeps(): RemoteCliDeps {
  return {
    authenticate: (reason) => authenticate(reason),
    loadVault,
    updateVault: (mutator) => updateVault(mutator),
    now: () => Date.now(),
    log: (line) => console.log(green(`✓ ${line}`)),
    error: (line) => console.error(red(`✗ ${line}`)),
    base: () => abraDir(),
    audit: appendAuditLog,
    hubNameForReceiver: defaultHubNameForReceiver,
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

export function defaultRemoteEnrollDeps(
  cli: RemoteCliDeps = defaultRemoteCliDeps(),
): RemoteEnrollDeps {
  return {
    authenticate: cli.authenticate,
    loadVault: cli.loadVault,
    updateVault: cli.updateVault,
    now: cli.now,
    log: cli.log,
    audit: cli.audit,
    base: cli.base?.(),
    fetchOffer: async (peerNameOrId) => {
      const vault = await cli.loadVault();
      const found = findPeer(vault, peerNameOrId);
      if (!found) throw new Error(`no paired peer named "${peerNameOrId}" — see: abra sync peers`);
      if (found.peer.role !== "receiver") {
        throw new Error(
          `peer "${found.peer.name}" is paired as ${found.peer.role} — only receivers can enroll`,
        );
      }
      const host = found.peer.lastAddress;
      if (!host) {
        throw new Error(
          `peer "${found.peer.name}" has no lastAddress — re-pair before remote enroll`,
        );
      }
      const hubName = (cli.hubNameForReceiver ?? defaultHubNameForReceiver)(vault);
      const out = await remoteEnrollViaHttp({
        host,
        port: REMOTE_UNLOCK_PORT,
        ca: found.peer.unlockWrap?.listenerCert,
        hubNameOrId: hubName,
        request: cli.request,
      });
      if (!out.ok) throw new Error(`enroll offer fetch failed: ${out.reason}`);
      return { offer: out.offer, listenerCert: out.listenerCert };
    },
  };
}

/**
 * Hub: `abra remote enroll <peer>` — feature flag, fetch sealed offer over PR 3
 * transport, Touch ID, store unlockWrap. Never logs wrap keys.
 */
export async function cmdRemoteEnroll(
  peerNameOrId: string,
  deps: RemoteEnrollDeps = defaultRemoteEnrollDeps(),
): Promise<void> {
  requireFlag();
  const fetched = await deps.fetchOffer(peerNameOrId);
  const { peerName } = await completeHubEnroll(fetched.offer, peerNameOrId, deps, {
    listenerCert: fetched.listenerCert,
  });
  (deps.audit ?? appendAuditLog)(
    { op: "enroll", peer: peerName, result: "ok" },
    { base: deps.base, now: deps.now },
  );
  deps.log?.(`enrolled remote unlock for "${peerName}"`);
}

export interface PeerBatchResult {
  peer: string;
  ok: boolean;
  reason?: string;
}

export interface RemoteUnlockCliOpts {
  all?: boolean;
  peers?: string;
  /** Requested idle lock duration (e.g. `5m`); receiver clamps to local cap. */
  idle?: string;
  /** Requested max unlock age (e.g. `1h`); receiver clamps to local cap. */
  maxAge?: string;
  /**
   * Keep-alive is not implemented: re-unlock always needs a fresh Touch ID.
   * Flag is refused so operators do not assume a silent loop.
   */
  keepAlive?: boolean;
}

/** One Touch ID for the batch, then parallel unlock per peer. */
export async function cmdRemoteUnlock(
  opts: RemoteUnlockCliOpts,
  deps: RemoteCliDeps = defaultRemoteCliDeps(),
): Promise<PeerBatchResult[]> {
  requireFlag();
  if (opts.keepAlive) {
    throw new Error(
      "--keep-alive is not supported — re-unlock always requires a fresh Touch ID (no silent loop)",
    );
  }

  const policy: UnlockPolicy = buildRequestedPolicy({
    idleSeconds: opts.idle !== undefined ? parsePolicyDuration(opts.idle, "idle") : undefined,
    maxAgeSeconds:
      opts.maxAge !== undefined ? parsePolicyDuration(opts.maxAge, "max-age") : undefined,
  });

  const before = await deps.loadVault();
  const selected = selectEnrolledPeers(before, opts);
  const names = selected.map((p) => p.name);
  await deps.authenticate(
    `abracadabra: remote unlock ${names.length === 1 ? names[0] : `${names.length} peers (${names.join(", ")})`}`,
  );

  // Re-load after auth — never hold the vault lock across Touch ID / network.
  const vault = await deps.loadVault();
  const identity = vault.syncIdentity;
  if (!identity) throw new Error("this vault has no sync identity — pair first (abra sync pair)");
  const peers = selectEnrolledPeers(vault, opts);

  const results = await Promise.all(
    peers.map(async (p): Promise<PeerBatchResult> => {
      try {
        const out = await remoteUnlockViaHttp({
          host: p.host,
          port: p.port,
          ca: peerCa(p),
          hubIdentity: identity,
          unlockWrap: p.unlockWrap,
          policy,
          now: deps.now,
          request: deps.request,
        });
        const result = out.ok ? "unlocked" : out.reason;
        (deps.audit ?? appendAuditLog)(
          { op: "unlock", peer: p.name, result },
          { base: deps.base?.(), now: deps.now },
        );
        if (out.ok) {
          const idle = out.policy.idleSeconds;
          const maxAge = out.policy.maxAgeSeconds;
          const policyNote =
            typeof idle === "number" && typeof maxAge === "number"
              ? ` (idle ${idle}s, max-age ${maxAge}s)`
              : "";
          deps.log?.(`unlocked ${p.name}${policyNote}`);
          return { peer: p.name, ok: true };
        }
        deps.error?.(`${p.name}: ${out.reason}`);
        return { peer: p.name, ok: false, reason: out.reason };
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        (deps.audit ?? appendAuditLog)(
          { op: "unlock", peer: p.name, result: "error" },
          { base: deps.base?.(), now: deps.now },
        );
        deps.error?.(`${p.name}: ${reason}`);
        return { peer: p.name, ok: false, reason };
      }
    }),
  );
  return results;
}

/** No Touch ID — signed lock request per peer, in parallel. */
export async function cmdRemoteLock(
  opts: { all?: boolean; peers?: string },
  deps: RemoteCliDeps = defaultRemoteCliDeps(),
): Promise<PeerBatchResult[]> {
  requireFlag();
  const vault = await deps.loadVault();
  const identity = vault.syncIdentity;
  if (!identity) throw new Error("this vault has no sync identity — pair first (abra sync pair)");
  const peers = selectEnrolledPeers(vault, opts);

  const results = await Promise.all(
    peers.map(async (p): Promise<PeerBatchResult> => {
      try {
        const out = await remoteLockViaHttp({
          host: p.host,
          port: p.port,
          ca: peerCa(p),
          hubIdentity: identity,
          peerDeviceId: p.unlockWrap.deviceId,
          now: deps.now,
          request: deps.request,
        });
        const result = out.ok ? "locked" : out.reason;
        (deps.audit ?? appendAuditLog)(
          { op: "lock", peer: p.name, result },
          { base: deps.base?.(), now: deps.now },
        );
        if (out.ok) {
          deps.log?.(`locked ${p.name}`);
          return { peer: p.name, ok: true };
        }
        deps.error?.(`${p.name}: ${out.reason}`);
        return { peer: p.name, ok: false, reason: out.reason };
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        (deps.audit ?? appendAuditLog)(
          { op: "lock", peer: p.name, result: "error" },
          { base: deps.base?.(), now: deps.now },
        );
        deps.error?.(`${p.name}: ${reason}`);
        return { peer: p.name, ok: false, reason };
      }
    }),
  );
  return results;
}

export interface RemoteStatusRow {
  peer: string;
  enrolled: boolean;
  reachable: boolean;
  locked: boolean | null;
  reason?: string;
}

/** Enrolled peers, reachable or not, locked or not — no secrets. */
export async function cmdRemoteStatus(
  deps: RemoteCliDeps = defaultRemoteCliDeps(),
): Promise<RemoteStatusRow[]> {
  // Status is safe without the feature flag (read-only probe of local enroll records).
  const vault = await deps.loadVault();
  const peers = listEnrolledPeers(vault);
  if (peers.length === 0) {
    deps.log?.("no enrolled remote-unlock peers");
    return [];
  }

  const rows = await Promise.all(
    peers.map(async (p): Promise<RemoteStatusRow> => {
      if (!p.host || !p.unlockWrap.listenerCert) {
        const row: RemoteStatusRow = {
          peer: p.name,
          enrolled: true,
          reachable: false,
          locked: null,
          reason: !p.host ? "no-address" : "no-cert",
        };
        console.log(
          `${p.name}  enrolled  unreachable  (${row.reason})`,
        );
        return row;
      }
      const out = await remoteStatusViaHttp({
        host: p.host,
        port: p.port,
        ca: p.unlockWrap.listenerCert,
        request: deps.request,
      });
      if (!out.ok) {
        const row: RemoteStatusRow = {
          peer: p.name,
          enrolled: true,
          reachable: false,
          locked: null,
          reason: out.reason,
        };
        console.log(`${p.name}  enrolled  unreachable  (${out.reason})`);
        return row;
      }
      const lockedLabel = out.locked ? "locked" : "unlocked";
      console.log(
        `${p.name}  enrolled  reachable  ${lockedLabel}${out.enrolled ? "" : dim(" (receiver not enrolled)")}`,
      );
      return {
        peer: p.name,
        enrolled: out.enrolled,
        reachable: true,
        locked: out.locked,
      };
    }),
  );
  return rows;
}

/** Hub: delete unlockWrap via updateVault (instant revoke); also revoke bot leases. */
export async function cmdRemoteRevoke(
  peerNameOrId: string,
  deps: RemoteCliDeps = defaultRemoteCliDeps(),
): Promise<void> {
  requireFlag();
  const before = await deps.loadVault();
  const found = findPeer(before, peerNameOrId);
  if (!found) throw new Error(`no paired peer named "${peerNameOrId}" — see: abra sync peers`);

  await deps.authenticate(`abracadabra: revoke remote unlock for ${found.peer.name}`);

  // Capture wrap + address before clearing (needed for lease revoke push).
  const wrapBefore = found.peer.unlockWrap;
  const hostBefore = found.peer.lastAddress;
  const peerSyncId = found.id;
  const peerNameBefore = found.peer.name;

  let cleared = false;
  let peerName = found.peer.name;
  let vaultAfter = before;
  await deps.updateVault((fresh) => {
    const out = clearPeerUnlockWrap(fresh, peerNameOrId);
    cleared = out.cleared;
    peerName = out.peerName ?? peerName;
    vaultAfter = out.vault;
    return out.vault;
  });

  // Network after vault write — never hold the vault lock across HTTPS.
  await revokePeerLeasesBestEffort({
    vault: vaultAfter.syncIdentity ? vaultAfter : before,
    peerName: peerNameBefore,
    peerSyncId,
    unlockWrap: wrapBefore,
    host: hostBefore,
    base: deps.base?.() ?? abraDir(),
    now: deps.now,
    request: deps.request,
    audit: deps.audit,
    log: deps.log,
    error: deps.error,
  });

  (deps.audit ?? appendAuditLog)(
    { op: "revoke", peer: peerName, result: cleared ? "ok" : "noop" },
    { base: deps.base?.(), now: deps.now },
  );
  if (cleared) deps.log?.(`revoked remote unlock for "${peerName}"`);
  else deps.log?.(`peer "${peerName}" had no remote unlock enrollment`);
}

/**
 * Receiver: delete unlock blob (+ hub pin) and stop the listener.
 * Local only — hub offline must not matter.
 */
export async function cmdRemoteDisable(
  deps: RemoteCliDeps = defaultRemoteCliDeps(),
): Promise<void> {
  requireFlag();
  const base = deps.base?.() ?? abraDir();
  clearUnlockBlob(base);
  clearHubPin(base);
  (deps.audit ?? appendAuditLog)(
    { op: "disable", result: "ok" },
    { base, now: deps.now },
  );
  await deps.afterDisable?.();
  deps.log?.("remote unlock disabled on this device (blob cleared; listener will stop)");
}

function fail(err: unknown): never {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(red(`✗ ${msg}`));
  process.exit(1);
}

function exitFromBatch(results: PeerBatchResult[]): void {
  process.exit(results.every((r) => r.ok) ? 0 : 1);
}

export function registerRemoteCommands(program: Command): void {
  const remote = program
    .command("remote")
    .description("Remote fleet unlock from the hub (requires ABRA_REMOTE_UNLOCK=1)");

  remote
    .command("whoami")
    .description("Print this device's remote public-key fingerprint (creates the device key if missing)")
    .action(() => {
      try {
        cmdRemoteWhoami();
      } catch (err) {
        fail(err);
      }
    });

  remote
    .command("enroll <peer>")
    .description(
      "Enroll a paired receiver for remote unlock (hub stores wrap key; requires ABRA_REMOTE_UNLOCK=1)",
    )
    .action(async (peer: string) => {
      try {
        await cmdRemoteEnroll(peer);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  remote
    .command("unlock")
    .description("Unlock enrolled peers (one Touch ID for the batch)")
    .option("--all", "unlock every enrolled receiver peer")
    .option("--peers <list>", "comma-separated peer names or ids")
    .option(
      "--idle <dur>",
      "request shorter idle lock (e.g. 5m); receiver clamps to local cap (default 15m)",
    )
    .option(
      "--max-age <dur>",
      "request shorter max unlock age (e.g. 1h); receiver clamps to local cap (default 8h)",
    )
    .option(
      "--keep-alive",
      "not supported — re-unlock always requires a fresh Touch ID (no silent loop)",
    )
    .action(
      async (opts: {
        all?: boolean;
        peers?: string;
        idle?: string;
        maxAge?: string;
        keepAlive?: boolean;
      }) => {
        try {
          const results = await cmdRemoteUnlock(opts);
          exitFromBatch(results);
        } catch (err) {
          fail(err);
        }
      },
    );

  remote
    .command("lock")
    .description("Lock enrolled peers (signed request; no Touch ID)")
    .option("--all", "lock every enrolled receiver peer")
    .option("--peers <list>", "comma-separated peer names or ids")
    .action(async (opts: { all?: boolean; peers?: string }) => {
      try {
        const results = await cmdRemoteLock(opts);
        exitFromBatch(results);
      } catch (err) {
        fail(err);
      }
    });

  remote
    .command("status")
    .description("Show enrolled peers: reachable / locked (no secrets)")
    .action(async () => {
      try {
        await cmdRemoteStatus();
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  remote
    .command("revoke <peer>")
    .description("Hub: delete the unlock wrap key for a peer (instant revoke)")
    .action(async (peer: string) => {
      try {
        await cmdRemoteRevoke(peer);
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });

  remote
    .command("disable")
    .description("Receiver: delete the unlock blob and stop the remote-unlock listener")
    .action(async () => {
      try {
        await cmdRemoteDisable();
        process.exit(0);
      } catch (err) {
        fail(err);
      }
    });
}
