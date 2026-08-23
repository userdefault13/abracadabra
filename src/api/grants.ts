/**
 * In-memory session grants: after one Touch ID approval, an app may silently
 * access a project's vars until the grant expires. Grants live only for the
 * lifetime of the `abra serve` process — restarting the daemon revokes them.
 */

export interface Grant {
  appId: string;
  project: string;
  expiresAt: number;
}

const grants = new Map<string, Grant>();

function key(appId: string, project: string): string {
  return `${appId}\u0000${project}`;
}

export function pruneGrants(): void {
  const now = Date.now();
  for (const [k, g] of grants) {
    if (g.expiresAt <= now) grants.delete(k);
  }
}

export function findGrant(appId: string, project: string): Grant | undefined {
  pruneGrants();
  return grants.get(key(appId, project));
}

export function issueGrant(appId: string, project: string, ttlSeconds: number): Grant {
  const grant: Grant = { appId, project, expiresAt: Date.now() + ttlSeconds * 1000 };
  grants.set(key(appId, project), grant);
  return grant;
}

export function listGrants(): Array<Grant & { remainingSec: number }> {
  pruneGrants();
  return [...grants.values()].map((g) => ({
    ...g,
    remainingSec: Math.max(0, Math.round((g.expiresAt - Date.now()) / 1000)),
  }));
}

export function revokeAll(): number {
  const n = grants.size;
  grants.clear();
  return n;
}
