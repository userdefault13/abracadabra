import fs from "node:fs";
import type { Vault, VarEntry, Connection } from "./vault.js";
import { syncStateFile, ensureDir } from "./paths.js";

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

export function loadSyncState(): SyncState | null {
  try {
    const raw = JSON.parse(fs.readFileSync(syncStateFile(), "utf8")) as SyncState;
    return raw && typeof raw === "object" && raw.base ? raw : null;
  } catch {
    return null;
  }
}

export function saveSyncState(vault: Vault): void {
  ensureDir();
  const state: SyncState = { lastSyncAt: Date.now(), base: vault };
  const file = syncStateFile();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
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
