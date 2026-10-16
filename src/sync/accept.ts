import type { SyncAcceptRule, Vault } from "../core/vault.js";
import { assertScopeNamesAllowed } from "../core/sync-scope.js";

/**
 * Inbound accept policy (`abra sync accept`), device-local in the vault.
 *
 * A rule matches a bundle when its `from` is the sender id (or "*") and its
 * `projects` is "*" or covers EVERY project in the bundle. Among matching
 * rules an explicit `auto: false` wins (manual review beats auto-apply);
 * otherwise any `auto: true` match applies. No match → queue.
 */

export type AcceptAction = "auto" | "queue";

export function decideAccept(
  rules: SyncAcceptRule[] | undefined,
  fromPeerId: string,
  projects: string[],
): { action: AcceptAction; rule?: SyncAcceptRule } {
  const matches = (rules ?? []).filter(
    (r) =>
      (r.from === "*" || r.from === fromPeerId) &&
      (r.projects === "*" || projects.every((p) => (r.projects as string[]).includes(p))),
  );
  const manual = matches.find((r) => !r.auto);
  if (manual) return { action: "queue", rule: manual };
  const auto = matches.find((r) => r.auto);
  if (auto) return { action: "auto", rule: auto };
  return { action: "queue" };
}

export function normalizeRuleProjects(projects: string[] | "*"): string[] | "*" {
  if (projects === "*") return "*";
  return [...assertScopeNamesAllowed(projects)].sort();
}

/** `-p a,b` → sorted names; absent → "*" (all projects). */
export function parseProjectsOption(raw: string | undefined): string[] | "*" {
  if (raw === undefined) return "*";
  const names = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (names.length === 0) throw new Error("-p needs at least one project name");
  return normalizeRuleProjects(names);
}

function sameSelector(a: Pick<SyncAcceptRule, "from" | "projects">, b: Pick<SyncAcceptRule, "from" | "projects">): boolean {
  if (a.from !== b.from) return false;
  if (a.projects === "*" || b.projects === "*") return a.projects === b.projects;
  return a.projects.length === b.projects.length && a.projects.every((p, i) => p === (b.projects as string[])[i]);
}

/** Add a rule, replacing one with the same (from, projects) selector. Pure. */
export function upsertAcceptRule(
  vault: Vault,
  rule: SyncAcceptRule,
): { vault: Vault; action: "added" | "updated" } {
  const normalized: SyncAcceptRule = { from: rule.from, projects: normalizeRuleProjects(rule.projects), auto: rule.auto };
  const rules = [...(vault.syncAccept ?? [])];
  const idx = rules.findIndex((r) => sameSelector(r, normalized));
  if (idx >= 0) rules[idx] = normalized;
  else rules.push(normalized);
  return { vault: { ...vault, syncAccept: rules }, action: idx >= 0 ? "updated" : "added" };
}

/** Remove rules with exactly this (from, projects) selector. Pure. */
export function removeAcceptRules(
  vault: Vault,
  selector: Pick<SyncAcceptRule, "from" | "projects">,
): { vault: Vault; removed: number } {
  const normalized = { from: selector.from, projects: normalizeRuleProjects(selector.projects) };
  const before = vault.syncAccept ?? [];
  const after = before.filter((r) => !sameSelector(r, normalized));
  return { vault: { ...vault, syncAccept: after }, removed: before.length - after.length };
}

export function describeAcceptRule(vault: Vault, rule: SyncAcceptRule): string {
  const from = rule.from === "*" ? "all sources" : vault.syncPeers?.[rule.from]?.name ?? `${rule.from} (unpaired)`;
  const projects = rule.projects === "*" ? "all projects" : rule.projects.join(", ");
  return `${rule.auto ? "auto-apply" : "queue"}  from ${from}  ·  ${projects}`;
}
