export interface VarInfo {
  masked: string;
  secret: boolean;
  updatedAt: number;
}

export interface ApiError {
  error: string;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as ApiError).error ?? `HTTP ${res.status}`);
  return data as T;
}

export function getProjects() {
  return request<{ projects: Record<string, Record<string, VarInfo>> }>("GET", "/api/projects");
}

export function createProject(name: string) {
  return request<{ ok: boolean }>("POST", "/api/projects", { name });
}

export function deleteProject(name: string) {
  return request<{ ok: boolean }>("DELETE", `/api/projects/${encodeURIComponent(name)}`);
}

export function createVar(project: string, key: string, value: string, secret: boolean) {
  return request<{ ok: boolean }>(
    "POST",
    `/api/projects/${encodeURIComponent(project)}/vars`,
    { key, value, secret },
  );
}

export function updateVar(project: string, key: string, value: string) {
  return request<{ ok: boolean }>(
    "PUT",
    `/api/projects/${encodeURIComponent(project)}/vars/${encodeURIComponent(key)}`,
    { value },
  );
}

export function deleteVar(project: string, key: string) {
  return request<{ ok: boolean }>(
    "DELETE",
    `/api/projects/${encodeURIComponent(project)}/vars/${encodeURIComponent(key)}`,
  );
}

/** Touch ID fires server-side; returns the raw value. */
export function revealVar(project: string, key: string) {
  return request<{ value: string }>(
    "GET",
    `/api/projects/${encodeURIComponent(project)}/vars/${encodeURIComponent(key)}`,
  );
}

export function getConnections() {
  return request<{
    connections: { provider: string; label?: string; createdAt: number; credentials: string[] }[];
  }>("GET", "/api/connections");
}

export function deleteConnection(provider: string) {
  return request<{ ok: boolean }>(
    "DELETE",
    `/api/connections/${encodeURIComponent(provider)}`,
  );
}

export function getGrants() {
  return request<{
    grants: { appId: string; project: string; remainingSec: number }[];
  }>("GET", "/grants");
}

export function revokeGrants() {
  return request<{ revoked: number }>("DELETE", "/grants");
}
