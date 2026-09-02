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

/** Manual resolutions keyed "<scope>/<key>"; undefined value = delete. */
export type Resolutions = Map<string, VarEntry | undefined>;

type VarMap = Record<string, VarEntry>;

const SYNC_MAGIC = "abracadabra-sync-state";

interface EncryptedSyncFile {
  format: typeof SYNC_MAGIC;
  version: 1;
  iv: string;
  tag: string;
  data: string;
}

function encryptSyncState(state: SyncState, key: Buffer): EncryptedSyncFile {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(state), "utf8");
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: SYNC_MAGIC,
    version: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

function decryptSyncState(file: EncryptedSyncFile, key: Buffer): SyncState {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(file.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(file.data, "base64")),
    decipher.final(),
  ]);
  const state = JSON.parse(plaintext.toString("utf8")) as SyncState;
  if (!state?.base) throw new Error("Invalid sync-state payload");
  return state;
}

function isEncryptedSyncFile(raw: unknown): raw is EncryptedSyncFile {
  return (
    typeof raw === "object" &&
    raw !== null &&
    (raw as EncryptedSyncFile).format === SYNC_MAGIC &&
    typeof (raw as EncryptedSyncFile).data === "string"
  );
}

function isLegacyPlainSyncState(raw: unknown): raw is SyncState {
  return (
    typeof raw === "object" &&
    raw !== null &&
    !(raw as { format?: string }).format &&
    typeof (raw as SyncState).base === "object" &&
    (raw as SyncState).base !== null
  );
}

/** Load last sync snapshot (encrypted with master key). Migrates legacy plaintext once. */
export async function loadSyncState(): Promise<SyncState | null> {
  try {
    const raw = JSON.parse(fs.readFileSync(syncStateFile(), "utf8")) as unknown;
    if (isLegacyPlainSyncState(raw)) {
      await saveSyncState(raw.base);
      return raw;
    }
    if (!isEncryptedSyncFile(raw)) return null;
    const key = await getMasterKey();
    return decryptSyncState(raw, key);
  } catch {
    return null;
  }
}

/** Persist sync base encrypted with the Keychain/master key (mode 0600). */
export async function saveSyncState(vault: Vault): Promise<void> {
  ensureDir();
  const key = await getMasterKey();
  const state: SyncState = { lastSyncAt: Date.now(), base: vault };
  const enc = encryptSyncState(state, key);
  const file = syncStateFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(enc), { mode: 0o600 });
  fs.renameSync(tmp, file);
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
    } else if (o && t) {
      if (o.updatedAt >= t.updatedAt) merged[key] = o;
      else merged[key] = t;
      if (o.updatedAt === t.updatedAt) conflicts.push({ scope, key, ours: o, theirs: t });
    } else {
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
): { projects: Vault["projects"]; report: string[] } {
  const report: string[] = [];
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
        report.push(
          `− project ${bold(name)} was deleted on ${o ? `${peerLabel} (removing here)` : `this machine (removing from ${peerLabel})`}`,
        );
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
  return { projects: mergedProjects, report };
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
): { merged: Vault; conflicts: Conflict[]; report: string[] } {
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
  };
}
