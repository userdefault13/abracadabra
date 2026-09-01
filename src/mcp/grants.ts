/**
 * In-memory session grants for the MCP server. After one Touch ID approval,
 * the same agent identity may silently re-read a project's vars until expiry.
 * Grants live only for the lifetime of the `abra mcp` process.
 */

export interface McpGrant {
  agentId: string;
  project: string;
  expiresAt: number;
}

const grants = new Map<string, McpGrant>();

function key(agentId: string, project: string): string {
  return `${agentId}\u0000${project}`;
}

export function pruneMcpGrants(): void {
  const now = Date.now();
  for (const [k, g] of grants) {
    if (g.expiresAt <= now) grants.delete(k);
  }
}

export function findMcpGrant(agentId: string, project: string): McpGrant | undefined {
  pruneMcpGrants();
  return grants.get(key(agentId, project));
}

export function issueMcpGrant(agentId: string, project: string, ttlSeconds: number): McpGrant {
  const grant: McpGrant = { agentId, project, expiresAt: Date.now() + ttlSeconds * 1000 };
  grants.set(key(agentId, project), grant);
  return grant;
}

export function listMcpGrants(): Array<McpGrant & { remainingSec: number }> {
  pruneMcpGrants();
  return [...grants.values()].map((g) => ({
    ...g,
    remainingSec: Math.max(0, Math.round((g.expiresAt - Date.now()) / 1000)),
  }));
}

export function revokeAllMcpGrants(): number {
  const n = grants.size;
  grants.clear();
  return n;
}
