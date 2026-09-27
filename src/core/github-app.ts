import crypto from "node:crypto";
import type { GithubGrant, GithubPermissionLevel, Vault } from "./vault.js";

/**
 * GitHub App installation tokens for agents.
 *
 * GitHub has no API for minting personal access tokens. An App installation can
 * mint tokens on demand, each limited to a subset of the installation's repos and
 * permissions and valid for one hour. abra keeps the App's private key and mints
 * per API key, clamped to that key's `github` grant.
 */

export const GITHUB_PROVIDER = "github";
export const GITHUB_VARS = {
  appId: "GITHUB_APP_ID",
  installationId: "GITHUB_APP_INSTALLATION_ID",
  privateKey: "GITHUB_APP_PRIVATE_KEY",
} as const;

/** Reuse a cached token until this long before GitHub expires it. */
const REFRESH_MARGIN_MS = 5 * 60_000;

export interface GithubAppCredentials {
  appId: string;
  installationId: string;
  privateKey: string;
}

export interface MintedToken {
  token: string;
  expiresAt: string;
  repositories: string[];
  permissions: Record<string, GithubPermissionLevel>;
}

export class GithubScopeError extends Error {}

export function githubApiBase(): string {
  return (process.env.ABRA_GITHUB_API_BASE || "https://api.github.com").replace(/\/+$/, "");
}

export function appCredentialsFromVault(vault: Vault): GithubAppCredentials | null {
  const vars = vault.connections?.[GITHUB_PROVIDER]?.vars;
  const appId = vars?.[GITHUB_VARS.appId]?.value;
  const installationId = vars?.[GITHUB_VARS.installationId]?.value;
  const privateKey = vars?.[GITHUB_VARS.privateKey]?.value;
  if (!appId || !installationId || !privateKey) return null;
  return { appId, installationId, privateKey };
}

/** RS256 app JWT. Backdated 60 s for clock skew; GitHub caps lifetime at 10 min. */
export function githubAppJwt(appId: string, privateKey: string, nowMs = Date.now()): string {
  const now = Math.floor(nowMs / 1000);
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const unsigned = `${b64({ alg: "RS256", typ: "JWT" })}.${b64({ iat: now - 60, exp: now + 540, iss: appId })}`;
  const signature = crypto.createSign("RSA-SHA256").update(unsigned).sign(privateKey).toString("base64url");
  return `${unsigned}.${signature}`;
}

function repoName(r: string): string {
  const name = r.trim().split("/").pop() ?? "";
  return name.toLowerCase();
}

const LEVEL: Record<GithubPermissionLevel, number> = { read: 1, write: 2 };

export function parseGrant(repos: string, perms: string): GithubGrant {
  const repositories = [...new Set(repos.split(",").map(repoName).filter(Boolean))];
  if (repositories.length === 0) throw new GithubScopeError("at least one repository is required");
  const permissions: Record<string, GithubPermissionLevel> = {};
  for (const pair of perms.split(",").map((p) => p.trim()).filter(Boolean)) {
    const [name, level] = pair.split(":").map((s) => s.trim());
    if (!/^[a-z_]+$/.test(name ?? "") || (level !== "read" && level !== "write")) {
      throw new GithubScopeError(`bad permission "${pair}" — use name:read or name:write`);
    }
    permissions[name] = level;
  }
  if (Object.keys(permissions).length === 0) throw new GithubScopeError("at least one permission is required");
  return { repositories, permissions };
}

/**
 * The scope actually minted: the request narrowed to the grant. Asking for
 * anything outside the grant is an error rather than a silent downgrade.
 */
export function resolveScope(
  grant: GithubGrant,
  requested: { repositories?: unknown; permissions?: unknown } = {},
): GithubGrant {
  const allowed = new Set(grant.repositories.map(repoName));
  let repositories = [...allowed];
  if (requested.repositories !== undefined) {
    if (!Array.isArray(requested.repositories) || requested.repositories.length === 0) {
      throw new GithubScopeError("repositories must be a non-empty array of repo names");
    }
    repositories = [...new Set(requested.repositories.map((r) => repoName(String(r))))];
    const outside = repositories.filter((r) => !allowed.has(r));
    if (outside.length) throw new GithubScopeError(`not granted: ${outside.join(", ")}`);
  }

  let permissions = { ...grant.permissions };
  if (requested.permissions !== undefined) {
    if (!requested.permissions || typeof requested.permissions !== "object" || Array.isArray(requested.permissions)) {
      throw new GithubScopeError('permissions must be an object like {"contents":"read"}');
    }
    permissions = {};
    for (const [name, level] of Object.entries(requested.permissions as Record<string, unknown>)) {
      const max = grant.permissions[name];
      if (level !== "read" && level !== "write") throw new GithubScopeError(`bad level for ${name}: ${String(level)}`);
      if (!max || LEVEL[level] > LEVEL[max]) throw new GithubScopeError(`not granted: ${name}:${level}`);
      permissions[name] = level;
    }
    if (Object.keys(permissions).length === 0) throw new GithubScopeError("permissions must not be empty");
  }
  return { repositories: repositories.sort(), permissions };
}

const cache = new Map<string, MintedToken>();

export function clearTokenCache(): void {
  cache.clear();
}

export async function mintInstallationToken(
  creds: GithubAppCredentials,
  scope: GithubGrant,
  cacheKey?: string,
): Promise<MintedToken> {
  const key = cacheKey ? `${cacheKey}|${JSON.stringify(scope)}` : "";
  const hit = key ? cache.get(key) : undefined;
  if (hit && Date.parse(hit.expiresAt) - Date.now() > REFRESH_MARGIN_MS) return hit;

  const res = await fetch(`${githubApiBase()}/app/installations/${encodeURIComponent(creds.installationId)}/access_tokens`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${githubAppJwt(creds.appId, creds.privateKey)}`,
      "Content-Type": "application/json",
      "User-Agent": "abracadabra",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify({ repositories: scope.repositories, permissions: scope.permissions }),
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await res.json().catch(() => ({}))) as {
    token?: string;
    expires_at?: string;
    repositories?: { name: string }[];
    permissions?: Record<string, GithubPermissionLevel>;
    message?: string;
  };
  if (!res.ok || !body.token || !body.expires_at) {
    throw new Error(`GitHub refused the token request (${res.status}): ${body.message ?? "no message"}`);
  }
  const minted: MintedToken = {
    token: body.token,
    expiresAt: body.expires_at,
    repositories: (body.repositories ?? []).map((r) => r.name),
    permissions: body.permissions ?? scope.permissions,
  };
  if (key) cache.set(key, minted);
  return minted;
}

/** Confirms the App key signs and the installation exists; returns its account login. */
export async function verifyInstallation(creds: GithubAppCredentials): Promise<string> {
  const res = await fetch(`${githubApiBase()}/app/installations/${encodeURIComponent(creds.installationId)}`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${githubAppJwt(creds.appId, creds.privateKey)}`,
      "User-Agent": "abracadabra",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await res.json().catch(() => ({}))) as { account?: { login?: string }; message?: string };
  if (!res.ok) throw new Error(`GitHub rejected the App credentials (${res.status}): ${body.message ?? "no message"}`);
  return body.account?.login ?? "unknown";
}
