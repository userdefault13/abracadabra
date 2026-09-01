import fs from "node:fs";
import type { ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadVault, saveVault, assertProject } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { send } from "./http-utils.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const WEB_DIST = path.join(ROOT, "web", "dist");

export async function gate(reason: string): Promise<boolean> {
  try {
    await authenticate(reason);
    return true;
  } catch {
    return false;
  }
}

function mask(value: string): string {
  if (value.length <= 4) return "••••";
  return `${value.slice(0, 2)}${"•".repeat(8)}${value.slice(-2)}`;
}

/** GET /api/projects — masked listing */
export async function listProjects(res: ServerResponse): Promise<void> {
  const vault = await loadVault();
  const projects = Object.fromEntries(
    Object.entries(vault.projects)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, project]) => [
        name,
        Object.fromEntries(
          Object.entries(project.vars).map(([key, entry]) => [
            key,
            {
              masked: entry.secret ? mask(entry.value) : entry.value,
              secret: entry.secret,
              updatedAt: entry.updatedAt,
            },
          ]),
        ),
      ]),
  );
  send(res, 200, { projects });
}

/** POST /api/projects {name} */
export async function createProject(body: { name?: string }, res: ServerResponse): Promise<void> {
  const name = body.name?.trim();
  if (!name || /[^\w.-]/.test(name)) {
    send(res, 400, { error: "invalid project name" });
    return;
  }
  const vault = await loadVault();
  if (vault.projects[name]) {
    send(res, 409, { error: `project already exists: ${name}` });
    return;
  }
  if (!(await gate(`abracadabra: browser creates project "${name}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  vault.projects[name] = { createdAt: Date.now(), vars: {} };
  await saveVault(vault);
  console.log(`✓ dash: created project "${name}"`);
  send(res, 200, { ok: true, name });
}

/** DELETE /api/projects/:name */
export async function deleteProject(name: string, res: ServerResponse): Promise<void> {
  const vault = await loadVault();
  if (!vault.projects[name]) {
    send(res, 404, { error: `project not found: ${name}` });
    return;
  }
  if (!(await gate(`abracadabra: browser DELETES project "${name}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  delete vault.projects[name];
  await saveVault(vault);
  console.log(`✓ dash: deleted project "${name}"`);
  send(res, 200, { ok: true });
}

/** POST /api/projects/:p/vars {key, value, secret} */
export async function createVar(projectName: string, body: { key?: string; value?: string; secret?: boolean }, res: ServerResponse): Promise<void> {
  let vault: Vault;
  let project;
  try {
    vault = await loadVault();
    project = assertProject(vault, projectName);
  } catch (err) {
    send(res, 404, { error: err instanceof Error ? err.message : String(err) });
    return;
  }
  const key = body.key?.trim();
  if (!key || !body.value || /\s/.test(key)) {
    send(res, 400, { error: 'expected {"key": "...", "value": "...", "secret": bool}' });
    return;
  }
  if (key in project.vars) {
    send(res, 409, { error: `var already exists: ${key} (use PUT)` });
    return;
  }
  if (
    !(await gate(`abracadabra: browser adds ${key} to "${projectName}"`))
  ) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  project.vars[key] = {
    value: body.value,
    secret: body.secret !== false,
    updatedAt: Date.now(),
  };
  await saveVault(vault);
  console.log(`✓ dash: added ${key} to "${projectName}"`);
  send(res, 200, { ok: true });
}

/** PUT /api/projects/:p/vars/:key {value, secret?} */
export async function updateVar(projectName: string, key: string, body: { value?: string; secret?: boolean }, res: ServerResponse): Promise<void> {
  let vault: Vault;
  let project;
  try {
    vault = await loadVault();
    project = assertProject(vault, projectName);
  } catch (err) {
    send(res, 404, { error: err instanceof Error ? err.message : String(err) });
    return;
  }
  if (!project.vars[key] || !body.value) {
    send(res, 404, { error: `var not found: ${key}` });
    return;
  }
  if (!(await gate(`abracadabra: browser edits ${key} in "${projectName}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  project.vars[key] = {
    value: body.value,
    secret: body.secret ?? project.vars[key].secret,
    updatedAt: Date.now(),
  };
  await saveVault(vault);
  console.log(`✓ dash: updated ${key} in "${projectName}"`);
  send(res, 200, { ok: true });
}

/** DELETE /api/projects/:p/vars/:key */
export async function deleteVar(projectName: string, key: string, res: ServerResponse): Promise<void> {
  let vault: Vault;
  let project;
  try {
    vault = await loadVault();
    project = assertProject(vault, projectName);
  } catch (err) {
    send(res, 404, { error: err instanceof Error ? err.message : String(err) });
    return;
  }
  if (!project.vars[key]) {
    send(res, 404, { error: `var not found: ${key}` });
    return;
  }
  if (!(await gate(`abracadabra: browser DELETES ${key} from "${projectName}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  delete project.vars[key];
  await saveVault(vault);
  console.log(`✓ dash: deleted ${key} from "${projectName}"`);
  send(res, 200, { ok: true });
}

/** GET /api/projects/:p/vars/:key — reveal (Touch ID gated) */
export async function revealVar(projectName: string, key: string, res: ServerResponse): Promise<void> {
  let project;
  try {
    const vault = await loadVault();
    project = assertProject(vault, projectName);
  } catch (err) {
    send(res, 404, { error: err instanceof Error ? err.message : String(err) });
    return;
  }
  const entry = project.vars[key];
  if (!entry) {
    send(res, 404, { error: `var not found: ${key}` });
    return;
  }
  if (
    !(await gate(`abracadabra: browser reveals ${projectName}/${key}`))
  ) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  console.log(`✓ dash: revealed ${projectName}/${key}`);
  send(res, 200, { value: entry.value });
}

/** GET /api/connections */
export async function listConnections(res: ServerResponse): Promise<void> {
  const vault = await loadVault();
  const connections = Object.values(vault.connections ?? {}).map((c) => ({
    provider: c.provider,
    label: c.label,
    createdAt: c.createdAt,
    credentials: Object.keys(c.vars),
  }));
  send(res, 200, { connections });
}

/** DELETE /api/connections/:provider (Touch ID gated) */
export async function deleteConnection(provider: string, res: ServerResponse): Promise<void> {
  const vault = await loadVault();
  if (!vault.connections?.[provider]) {
    send(res, 404, { error: `no connection for ${provider}` });
    return;
  }
  if (!(await gate(`abracadabra: browser disconnects "${provider}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  delete vault.connections[provider];
  await saveVault(vault);
  console.log(`✓ dash: disconnected ${provider}`);
  send(res, 200, { ok: true });
}

// ─── USB backup & sync ──────────────────────────────────────────────────

/** GET /api/usb */
export async function listUsb(res: ServerResponse): Promise<void> {
  const { listVolumes } = await import("../commands/usb.js");
  send(res, 200, { volumes: listVolumes() });
}

interface UsbBackupBody {
  volume?: string;
  passphrase?: string;
}

/** POST /api/usb/backup {volume, passphrase} — Touch ID gated */
export async function usbBackup(body: UsbBackupBody, res: ServerResponse): Promise<void> {
  const volume = body.volume?.trim();
  if (!volume || !body.passphrase || body.passphrase.length < 8) {
    send(res, 400, { error: "expected {volume, passphrase (min 8 chars)}" });
    return;
  }
  const { createBackup } = await import("../commands/usb.js");
  try {
    const file = await createBackup(volume, body.passphrase);
    console.log(`✓ dash: wrote USB backup ${file}`);
    send(res, 200, { ok: true, file });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    send(res, /biometric/i.test(msg) ? 403 : 400, { error: msg });
  }
}

interface UsbSyncBody extends UsbBackupBody {
  target?: string;
  apply?: boolean;
  force?: "ours" | "theirs";
}

/**
 * POST /api/usb/sync
 *  - apply=false → dry-run preview {report, conflicts, needsResolution}
 *  - apply=true  → merge + write; 409 with conflicts[] when unresolved
 */
export async function usbSync(body: UsbSyncBody, res: ServerResponse): Promise<void> {
  if (!body.passphrase || body.passphrase.length < 8) {
    send(res, 400, { error: "expected {passphrase, target?, apply?, force?}" });
    return;
  }
  const { previewSync, applySync } = await import("../commands/usb.js");
  try {
    if (body.apply) {
      if (body.force && body.force !== "ours" && body.force !== "theirs") {
        send(res, 400, { error: 'force must be "ours" or "theirs"' });
        return;
      }
      const result = await applySync(body.target?.trim() || undefined, body.passphrase, body.force);
      send(res, 200, { ok: true, ...result, report: result.report, conflicts: [] });
    } else {
      const preview = await previewSync(body.target?.trim() || undefined, body.passphrase);
      send(res, 200, { ok: true, ...preview });
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if ((err as { conflicts?: unknown })?.conflicts) {
      const conflictErr = err as Error & { conflicts: { scope: string; key: string; newest: string; ours?: string; theirs?: string }[] };
      send(res, 409, { error: msg, conflicts: conflictErr.conflicts });
      return;
    }
    send(res, /biometric/i.test(msg) ? 403 : 400, { error: msg });
  }
}

// ─── API keys (bearer tokens for POST /secret) ──────────────────────────

/** GET /api/keys — metadata only, never full keys */
export async function listApiKeys(res: ServerResponse): Promise<void> {
  const vault = await loadVault();
  const keys = Object.values(vault.apiKeys ?? {})
    .sort((a, b) => a.createdAt - b.createdAt)
    .map((k) => ({
      id: k.id,
      name: k.name,
      prefix: k.prefix,
      projects: k.projects,
      createdAt: k.createdAt,
      expiresAt: k.expiresAt,
    }));
  send(res, 200, { keys });
}

/** POST /api/keys {name, projects?, expiresInDays?} — returns the full key ONCE (Touch ID gated) */
export async function createApiKey(body: { name?: string; projects?: unknown; expiresInDays?: number }, res: ServerResponse): Promise<void> {
  const name = body.name?.trim() ?? "";
  if (!/^[\w.-]{2,64}$/.test(name)) {
    send(res, 400, { error: "name must be 2-64 chars: letters, digits, . _ -" });
    return;
  }
  let projects: string[] | null = null;
  if (Array.isArray(body.projects) && body.projects.length > 0) {
    projects = body.projects.map(String);
  }
  const expiresInDays = Number.isFinite(body.expiresInDays) ? Number(body.expiresInDays) : 0;
  if (!(await gate(`abracadabra: browser issues API key "${name}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  const vault = await loadVault();
  for (const p of projects ?? []) {
    if (!vault.projects[p]) {
      send(res, 404, { error: `project not found: ${p}` });
      return;
    }
  }
  const { generateApiKey } = await import("../core/apikeys.js");
  const { record, fullKey } = generateApiKey(name, projects, {
    expiresInDays: expiresInDays > 0 ? expiresInDays : undefined,
  });
  vault.apiKeys![record.id] = record;
  await saveVault(vault);
  console.log(`✓ dash: issued API key "${name}" (${record.id})`);
  send(res, 200, { ok: true, key: { ...record }, fullKey }); // fullKey shown exactly once
}

/** DELETE /api/keys/:id — Touch ID gated */
export async function revokeApiKey(id: string, res: ServerResponse): Promise<void> {
  const vault = await loadVault();
  if (!vault.apiKeys?.[id]) {
    send(res, 404, { error: `no API key with id ${id}` });
    return;
  }
  if (!(await gate(`abracadabra: browser REVOKES API key "${vault.apiKeys[id].name}"`))) {
    send(res, 403, { error: "biometric approval denied" });
    return;
  }
  delete vault.apiKeys[id];
  await saveVault(vault);
  console.log(`✓ dash: revoked API key ${id}`);
  send(res, 200, { ok: true });
}

// ─── static file hosting ────────────────────────────────────────────────

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json",
  ".woff2": "font/woff2",
};

export function serveStatic(res: import("node:http").ServerResponse, pathname: string): boolean {
  if (!fs.existsSync(WEB_DIST)) return false;
  let rel = pathname === "/" ? "/index.html" : pathname;
  const filePath = path.join(WEB_DIST, rel);
  // path traversal guard
  if (!filePath.startsWith(WEB_DIST + path.sep) && filePath !== WEB_DIST) return false;

  let target = filePath;
  if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    // SPA fallback
    target = path.join(WEB_DIST, "index.html");
    if (!fs.existsSync(target)) return false;
  }
  const ext = path.extname(target);
  res.writeHead(200, {
    "Content-Type": MIME[ext] ?? "application/octet-stream",
    "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600",
  });
  fs.createReadStream(target).pipe(res);
  return true;
}

export function webDistMissing(): boolean {
  return !fs.existsSync(path.join(WEB_DIST, "index.html"));
}
