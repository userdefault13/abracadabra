import fs from "node:fs";
import type { ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadVault, saveVault, assertProject } from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { authenticate } from "../auth/touchid.js";
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
