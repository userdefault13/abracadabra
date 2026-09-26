import fs from "node:fs";
import crypto from "node:crypto";
import type { Vault, VarEntry, Connection } from "./vault.js";
import { syncStateFile, ensureDir } from "./paths.js";
import { getMasterKey } from "../platform/index.js";

const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;

export interface SyncState {
  lastSyncAt: number;
  base: Vault;
}

export interface Conflict {
  scope: string;
  key: string;
  ours?: VarEntry;
  theirs?: VarEntry;
}

export interface ProjectDeletion {
  project: string;
  /** "here" = deleted on this machine (would remove from peer); "peer" = deleted on peer (would remove here). */
  side: "here" | "peer";
}

/** Manual resolutions keyed "<scope>/<key>"; undefined value = delete. */
export type Resolutions = Map<string, VarEntry | undefined>;

type VarMap = Record<string, VarEntry>;

const SYNC_MAGIC = "abracadabra-sync-state";

interface EncryptedSyncFile {
  format: typeof SYNC_MAGIC;
  version: 1 | 2;
  iv: string;
  tag: string;
  data: string;
}

/** v2 plaintext: per-peer bases. */
interface SyncStateV2 {
  peers: Record<string, SyncState>;
}

function encryptBytes(plaintext: Buffer, key: Buffer): EncryptedSyncFile {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: SYNC_MAGIC,
    version: 2,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function decryptBytes(file: EncryptedSyncFile, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(file.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(file.data, "base64")),
    decipher.final(),
  ]);
}

function isEncryptedSyncFile(raw: unknown): raw is EncryptedSyncFile {
  return (
    typeof raw === "object" &&
    raw !== null &&
    (raw as EncryptedSyncFile).format === SYNC_MAGIC &&
    typeof (raw as EncryptedSyncFile).data === "string" &&
    ((raw as EncryptedSyncFile).version === 1 || (raw as EncryptedSyncFile).version === 2)
  );
}

function isLegacyPlainSyncState(raw: unknown): boolean {
  return (
    typeof raw === "object" &&
    raw !== null &&
    !(raw as { format?: string }).format &&
    typeof (raw as SyncState).base === "object" &&
    (raw as SyncState).base !== null
  );
}

async function readPeersMap(): Promise<Record<string, SyncState>> {
  try {
    const raw = JSON.parse(fs.readFileSync(syncStateFile(), "utf8")) as unknown;
    // Legacy plaintext or encrypted v1: never use as a base; next save replaces with v2.
    if (isLegacyPlainSyncState(raw)) return {};
    if (!isEncryptedSyncFile(raw)) return {};
    if (raw.version === 1) return {};
    const key = await getMasterKey();
    const plaintext = decryptBytes(raw, key);
    const parsed = JSON.parse(plaintext.toString("utf8")) as SyncStateV2;
    if (!parsed?.peers || typeof parsed.peers !== "object") return {};
    return parsed.peers;
  } catch {
    return {};
  }
}

/**
 * Load last sync snapshot for one peer (encrypted with master key).
 * Legacy v1 / plaintext sync-state is never used as a base (returns null).
 * Pass null/undefined peerId when the peer id is unavailable → additive merge.
 */
export async function loadSyncState(peerId: string | null | undefined): Promise<SyncState | null> {
  if (!peerId) return null;
  const peers = await readPeersMap();
  const entry = peers[peerId];
  if (!entry?.base) return null;
  return entry;
}

/**
 * Persist sync base for one peer (encrypted, mode 0600). Updates only that peer entry.
 * No-ops when peerId is missing (legacy peer without deviceId/lineageId).
 */
export async function saveSyncState(
  peerId: string | null | undefined,
  vault: Vault,
): Promise<void> {
  if (!peerId) return;
  ensureDir();
  const peers = await readPeersMap();
  peers[peerId] = { lastSyncAt: Date.now(), base: vault };
  const key = await getMasterKey();
  const enc = encryptBytes(Buffer.from(JSON.stringify({ peers } satisfies SyncStateV2), "utf8"), key);
  const file = syncStateFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** Peer id helpers — return null when the remote id is missing (legacy). */
export function usbPeerId(lineageId: string | undefined | null): string | null {
  return lineageId ? `usb:${lineageId}` : null;
}

export function lanPeerId(deviceId: string | undefined | null): string | null {
  return deviceId ? `lan:${deviceId}` : null;
}

function entryEq(a: VarEntry | undefined, b: VarEntry | undefined): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

function mergeVarMaps(
  scope: string,
  ours: VarMap,
  theirs: VarMap,
  base: VarMap,
  conflicts: Conflict[],
  resolutions: Resolutions,
): VarMap {
  const merged: VarMap = {};
  const keys = new Set([...Object.keys(ours), ...Object.keys(theirs)]);
  for (const key of keys) {
    const o = ours[key];
    const t = theirs[key];
    const b = base[key];
    if (entryEq(o, t)) {
      if (o) merged[key] = o;
      continue;
    }
    const manual = resolutions.get(`${scope}/${key}`);
    if (manual !== undefined || resolutions.has(`${scope}/${key}`)) {
      if (manual) merged[key] = manual;
      continue;
    }
    const oursChanged = !entryEq(o, b);
    const theirsChanged = !entryEq(t, b);
    if (!theirsChanged) {
      if (o) merged[key] = o;
    } else if (!oursChanged) {
      if (t) merged[key] = t;
    } else {
      // Both sides changed relative to base (including no base) and differ → conflict.
      conflicts.push({ scope, key, ours: o, theirs: t });
    }
  }
  return merged;
}

function mergeProjects(
  ours: Vault,
  theirs: Vault,
  base: Vault | null,
  conflicts: Conflict[],
  resolutions: Resolutions,
  peerLabel: string,
): {
  projects: Vault["projects"];
  report: string[];
  projectDeletions: ProjectDeletion[];
} {
  const report: string[] = [];
  const projectDeletions: ProjectDeletion[] = [];
  const mergedProjects: Vault["projects"] = {};
  const bProjects = base?.projects ?? {};
  const scopes = new Set([...Object.keys(ours.projects), ...Object.keys(theirs.projects)]);

  for (const name of [...scopes].sort()) {
    const o = ours.projects[name];
    const t = theirs.projects[name];
    const b = bProjects[name];
    if (!o || !t) {
      const winner = o ?? t!;
      const existedInBase = Boolean(b);
      if (!existedInBase) {
        mergedProjects[name] = winner;
        report.push(
          o
            ? `+ project ${bold(name)} pushed to ${peerLabel}`
            : `+ project ${bold(name)} pulled from ${peerLabel}`,
        );
      } else {
        // Whole-project deletion relative to base — gated by callers via --allow-deletes.
        const side: ProjectDeletion["side"] = o ? "peer" : "here";
        projectDeletions.push({ project: name, side });
        report.push(
          `− project ${bold(name)} was deleted on ${
            o ? `${peerLabel} (removing here)` : `this machine (removing from ${peerLabel})`
          }`,
        );
        // Do not keep the survivor — deletion applies when allowed.
      }
      continue;
    }
    const vars = mergeVarMaps(name, o.vars, t.vars, b?.vars ?? {}, conflicts, resolutions);
    mergedProjects[name] = { createdAt: o.createdAt, vars };
    if (JSON.stringify(vars) !== JSON.stringify(o.vars)) {
      const diff = Object.keys(vars).length - Object.keys(o.vars).length;
      report.push(
        diff === 0
          ? `~ vars updated in ${bold(name)}`
          : diff > 0
            ? `+ ${diff} var(s) added to ${bold(name)}`
            : `− ${-diff} var(s) removed from ${bold(name)}`,
      );
    }
  }
  return { projects: mergedProjects, report, projectDeletions };
}

function mergeConnections(
  ours: Vault,
  theirs: Vault,
  base: Vault | null,
  conflicts: Conflict[],
  resolutions: Resolutions,
): { connections: NonNullable<Vault["connections"]>; report: string[] } {
  const report: string[] = [];
  const merged: NonNullable<Vault["connections"]> = {};
  const connScopes = new Set([
    ...Object.keys(ours.connections ?? {}),
    ...Object.keys(theirs.connections ?? {}),
  ]);
  const bConns = base?.connections ?? {};
  for (const provider of [...connScopes].sort()) {
    const o: Connection | undefined = ours.connections?.[provider];
    const t: Connection | undefined = theirs.connections?.[provider];
    const b = bConns[provider];
    if (o && t) {
      const vars = mergeVarMaps(
        `connections/${provider}`,
        o.vars,
        t.vars,
        b?.vars ?? {},
        conflicts,
        resolutions,
      );
      merged[provider] = { ...o, meta: { ...t.meta, ...o.meta }, vars };
    } else {
      merged[provider] = (o ?? t)!;
      report.push(`~ connection ${bold(provider)} synced`);
    }
  }
  return { connections: merged, report };
}

export function threeWayMerge(
  ours: Vault,
  theirs: Vault,
  base: Vault | null,
  resolutions: Resolutions,
  peerLabel = "peer",
): {
  merged: Vault;
  conflicts: Conflict[];
  report: string[];
  projectDeletions: ProjectDeletion[];
} {
  const conflicts: Conflict[] = [];
  const projects = mergeProjects(ours, theirs, base, conflicts, resolutions, peerLabel);
  const conns = mergeConnections(ours, theirs, base, conflicts, resolutions);

  const oP = JSON.stringify(ours.passkeys ?? []);
  const tP = JSON.stringify(theirs.passkeys ?? []);
  const bP = JSON.stringify(base?.passkeys ?? []);
  const passkeys = oP !== bP ? ours.passkeys : theirs.passkeys;
  const oK = JSON.stringify(ours.apiKeys ?? {});
  const tK = JSON.stringify(theirs.apiKeys ?? {});
  const bK = JSON.stringify(base?.apiKeys ?? {});
  const apiKeys = oK !== bK ? ours.apiKeys : theirs.apiKeys;

  return {
    merged: {
      version: 1,
      projects: projects.projects,
      connections: conns.connections,
      passkeys,
      apiKeys,
    },
    conflicts,
    report: [...projects.report, ...conns.report],
    projectDeletions: projects.projectDeletions,
  };
}

/** Red dry-run lines for whole-project deletions (shown at top of report). */
export function formatProjectDeletionLines(
  deletions: ProjectDeletion[],
  peerLabel = "peer",
): string[] {
  const red = (s: string) => `\x1b[31m${s}\x1b[0m`;
  return deletions.map((d) =>
    red(
      d.side === "peer"
        ? `DELETE project ${d.project} (deleted on ${peerLabel} — would remove here)`
        : `DELETE project ${d.project} (deleted here — would remove from ${peerLabel})`,
    ),
  );
}
