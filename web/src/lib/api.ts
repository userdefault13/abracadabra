import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";

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
  if (res.status === 401) {
    // session expired / locked — let the app re-show the login gate
    window.dispatchEvent(new CustomEvent("abra:unauthorized"));
  }
  if (!res.ok) throw new Error((data as ApiError).error ?? `HTTP ${res.status}`);
  return data as T;
}

export function getSession() {
  return request<{ authenticated: boolean; passkeys: number }>("GET", "/api/session");
}

export function logout() {
  return request<{ ok: boolean }>("DELETE", "/api/session");
}

export function passkeyRegisterOptions() {
  return request<PublicKeyCredentialCreationOptionsJSON>(
    "POST",
    "/api/passkey/register/options",
    {},
  );
}

export function passkeyRegisterVerify(response: RegistrationResponseJSON) {
  return request<{ ok: boolean }>("POST", "/api/passkey/register/verify", response);
}

export function passkeyAuthOptions() {
  return request<PublicKeyCredentialRequestOptionsJSON>("POST", "/api/passkey/auth/options", {});
}

export function passkeyAuthVerify(response: AuthenticationResponseJSON) {
  return request<{ ok: boolean }>("POST", "/api/passkey/auth/verify", response);
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

// ── USB backup & sync ─────────────────────────────────────────────────────

export interface UsbVolume {
  name: string;
  mount: string;
  backupFile?: string;
  backupAt?: number;
}

export interface UsbConflict {
  scope: string;
  key: string;
  newest: "ours" | "theirs";
  ours?: string;
  theirs?: string;
}

export interface UsbSyncResponse {
  ok: boolean;
  report?: string[];
  conflicts?: UsbConflict[];
  needsResolution?: boolean;
  changed?: boolean;
  file?: string;
}

export function listUsb() {
  return request<{ volumes: UsbVolume[] }>("GET", "/api/usb");
}

export function usbBackup(volume: string, passphrase: string) {
  return request<{ ok: true; file: string }>("POST", "/api/usb/backup", {
    volume,
    passphrase,
  });
}

export function usbSync(body: {
  target?: string;
  passphrase: string;
  apply: boolean;
  force?: "ours" | "theirs";
}) {
  return request<UsbSyncResponse>("POST", "/api/usb/sync", body);
}

// ── API keys (bearer tokens for POST /secret) ─────────────────────────────

export interface ApiKeyInfo {
  id: string;
  name: string;
  prefix: string;
  projects: string[] | null;
  createdAt: number;
  expiresAt?: number;
}

export function listApiKeys() {
  return request<{ keys: ApiKeyInfo[] }>("GET", "/api/keys");
}

export function createApiKey(body: { name: string; projects?: string[]; expiresInDays?: number }) {
  return request<{ ok: true; key: ApiKeyInfo; fullKey: string }>("POST", "/api/keys", body);
}

export function revokeApiKey(id: string) {
  return request<{ ok: true }>("DELETE", `/api/keys/${encodeURIComponent(id)}`);
}
