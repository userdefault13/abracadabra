import type { Project, Vault, VarEntry } from "./vault.js";
import { RESERVED_PROJECT_PREFIX, TREASURY_PROJECT } from "./vault.js";

export interface ScopedMergeReport {
  newProjects: { project: string; keys: number }[];
  added: { project: string; key: string }[];
  changed: { project: string; key: string }[];
  conflicts: { project: string; key: string }[];
}

export interface ScopedMergeResult {
  merged: Vault;
  report: ScopedMergeReport;
  changed: boolean;
}

/** Refuse treasury / reserved project names (no vault needed — host can fail early). */
export function assertScopeNamesAllowed(names: string[]): string[] {
  if (!Array.isArray(names) || names.length === 0) {
    throw new Error("scoped sync requires at least one project name");
  }
  const cleaned: string[] = [];
  const seen = new Set<string>();
  for (const raw of names) {
    const name = typeof raw === "string" ? raw.trim() : "";
    if (!name) throw new Error("scoped sync project name must be non-empty");
    if (name === TREASURY_PROJECT || name.startsWith(RESERVED_PROJECT_PREFIX)) {
      throw new Error(
        `refused: project "${name}" is reserved (${RESERVED_PROJECT_PREFIX}* / treasury) and cannot be synced`,
      );
    }
    if (seen.has(name)) continue;
    seen.add(name);
    cleaned.push(name);
  }
  if (cleaned.length === 0) {
    throw new Error("scoped sync requires at least one project name");
  }
  return cleaned;
}

/** Validate names against a vault: allowed + known. Returns deduped trimmed names. */
export function validateScope(vault: Vault, names: string[]): string[] {
  const cleaned = assertScopeNamesAllowed(names);
  const unknown = cleaned.filter((n) => !vault.projects[n]);
  if (unknown.length > 0) {
    throw new Error(`unknown project(s): ${unknown.join(", ")}`);
  }
  return cleaned;
}

/** Deep-copy only the named projects (must already be validated). */
export function extractScopedProjects(
  vault: Vault,
  names: string[],
): Record<string, Project> {
  const out: Record<string, Project> = {};
  for (const name of names) {
    const p = vault.projects[name];
    if (!p) throw new Error(`unknown project(s): ${name}`);
    out[name] = structuredClone(p);
  }
  return out;
}

function entryContentEq(a: VarEntry, b: VarEntry): boolean {
  return a.value === b.value && a.secret === b.secret;
}

/**
 * Merge incoming scoped projects into local vault.
 * Only touches projects present in `incoming`; never deletes; conflicts keep local unless theirs.
 * Does not mutate inputs. Does not touch sync-state.json.
 */
export function mergeScopedProjects(
  local: Vault,
  incoming: Record<string, Project>,
  opts: { theirs?: boolean } = {},
): ScopedMergeResult {
  const theirs = opts.theirs === true;
  const report: ScopedMergeReport = {
    newProjects: [],
    added: [],
    changed: [],
    conflicts: [],
  };

  const merged: Vault = {
    version: 1,
    projects: structuredClone(local.projects),
    connections: local.connections ? structuredClone(local.connections) : undefined,
    passkeys: local.passkeys ? structuredClone(local.passkeys) : undefined,
    apiKeys: local.apiKeys ? structuredClone(local.apiKeys) : undefined,
  };

  for (const [projectName, incomingProject] of Object.entries(incoming)) {
    const localProject = merged.projects[projectName];
    if (!localProject) {
      merged.projects[projectName] = structuredClone(incomingProject);
      report.newProjects.push({
        project: projectName,
        keys: Object.keys(incomingProject.vars).length,
      });
      continue;
    }

    const vars: Record<string, VarEntry> = { ...localProject.vars };
    for (const [key, incomingEntry] of Object.entries(incomingProject.vars)) {
      const localEntry = vars[key];
      if (!localEntry) {
        vars[key] = structuredClone(incomingEntry);
        report.added.push({ project: projectName, key });
        continue;
      }
      if (entryContentEq(localEntry, incomingEntry)) {
        // unchanged — keep local (including updatedAt)
        continue;
      }
      if (theirs) {
        vars[key] = structuredClone(incomingEntry);
        report.changed.push({ project: projectName, key });
      } else {
        // keep local; record conflict
        report.conflicts.push({ project: projectName, key });
      }
    }
    merged.projects[projectName] = {
      createdAt: localProject.createdAt,
      vars,
    };
  }

  const changed =
    report.newProjects.length > 0 ||
    report.added.length > 0 ||
    report.changed.length > 0;

  return { merged, report, changed };
}

/** Human-readable report lines — project/key NAMES only, never values. */
export function formatScopedReport(report: ScopedMergeReport): string[] {
  const lines: string[] = [];
  for (const { project, keys } of report.newProjects) {
    lines.push(`+ project ${project} (new, ${keys} keys)`);
  }
  for (const { project, key } of report.added) {
    lines.push(`+ ${project}/${key} added`);
  }
  for (const { project, key } of report.changed) {
    lines.push(`~ ${project}/${key} taken from host (--theirs)`);
  }
  for (const { project, key } of report.conflicts) {
    lines.push(
      `! ${project}/${key} conflict — kept this machine's value (use --theirs to take the host's)`,
    );
  }
  return lines;
}
