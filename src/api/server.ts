import http from "node:http";
import { loadVault, assertProject } from "../core/vault.js";
import { authenticate } from "../platform/index.js";
import { identifyPeer } from "./identify.js";
import { findGrant, issueGrant, listGrants, revokeAll } from "./grants.js";
import { send } from "./http-utils.js";
import * as dash from "./dash.js";
import * as session from "./session.js";
import * as passkeys from "./passkeys.js";
import * as licenseDash from "./license-dash.js";
import { isLicensed, licenseEnforcementEnabled } from "../license/index.js";

const MAX_BODY = 64 * 1024;
const MAX_TTL_SECONDS = 24 * 60 * 60;

let authChain: Promise<unknown> = Promise.resolve();

/** Serialize biometric prompts so parallel requests queue instead of stacking dialogs. */
function enqueueAuth<T>(fn: () => Promise<T>): Promise<T> {
  const next = authChain.then(fn, fn);
  authChain = next.catch(() => {});
  return next;
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

interface SecretRequest {
  project?: string;
  keys?: string[];
  /** Request a session grant: silent access for this app+project for N seconds. */
  ttl?: number;
}

export function createApiServer(): http.Server {
  return http.createServer((req, res) => {
    void handleRequest(req, res);
  });
}

async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  try {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const pathname = url.pathname;
    const method = req.method ?? "GET";

    if (method === "OPTIONS") {
      send(res, 204, {});
      return;
    }

    if (method === "GET" && pathname === "/health") {
      send(res, 200, { ok: true, service: "abracadabra" });
      return;
    }

    // ── web dash API ──────────────────────────────────────────────
    if (pathname.startsWith("/api/")) {
          const parts = pathname.split("/").filter(Boolean); // ["api", ...]
          const readJson = async (): Promise<Record<string, unknown>> => {
            try {
              return JSON.parse((await readBody(req)) || "{}");
            } catch {
              return { __invalid: true };
            }
          };
          // dash auth: passkey (WebAuthn) login + session status/logout —
          // the only /api routes reachable pre-auth
          if (parts[1] === "session") {
            if (method === "GET" && parts.length === 2) {
              const vault = await loadVault();
              send(res, 200, {
                authenticated: session.isAuthed(req),
                passkeys: vault.passkeys?.length ?? 0,
              });
              return;
            }
            if (method === "DELETE" && parts.length === 2) return session.logout(res);
            send(res, 404, { error: "not found" });
            return;
          }
          if (parts[1] === "passkey") {
            const sub = parts[2];
            if (method === "POST" && sub === "register" && parts[3] === "options")
              return await passkeys.registerOptions(req, res);
            if (method === "POST" && sub === "register" && parts[3] === "verify")
              return await passkeys.registerVerify(req, await readJson(), res);
            if (method === "POST" && sub === "auth" && parts[3] === "options")
              return await passkeys.authOptions(req, res);
            if (method === "POST" && sub === "auth" && parts[3] === "verify")
              return await passkeys.authVerify(req, await readJson(), res);
            send(res, 404, { error: "not found" });
            return;
          }
          if (parts[1] === "license") {
            if (method === "GET" && parts[2] === "status" && parts.length === 3)
              return await licenseDash.licenseStatus(res);
            if (method === "POST" && parts[2] === "activate" && parts.length === 3)
              return await licenseDash.licenseActivate(await readJson(), res);
            send(res, 404, { error: "not found" });
            return;
          }
          if (licenseEnforcementEnabled() && !(await isLicensed())) {
            send(res, 403, {
              error: "license_required",
              message: "Abra License NFT required — activate via abra activate or the web dash",
            });
            return;
          }
          // everything else requires an authenticated dash session
          if (!session.isAuthed(req)) {
            send(res, 401, { error: "2FA login required" });
            return;
          }
          // /api/projects[...]
          if (parts[1] === "projects") {
            const project = decodeURIComponent(parts[2] ?? "");
            const key = decodeURIComponent(parts[4] ?? "");
            if (method === "GET" && parts.length === 2) return await dash.listProjects(res);
            if (method === "POST" && parts.length === 2)
              return await dash.createProject(await readJson(), res);
            if (method === "DELETE" && parts.length === 3) return await dash.deleteProject(project, res);
            if (method === "POST" && parts.length === 4)
              return await dash.createVar(project, await readJson(), res);
            if (method === "PUT" && parts.length === 5)
              return await dash.updateVar(project, key, await readJson(), res);
            if (method === "DELETE" && parts.length === 5) return await dash.deleteVar(project, key, res);
            if (method === "GET" && parts.length === 5) return await dash.revealVar(project, key, res);
          }
          if (parts[1] === "connections") {
            if (method === "GET" && parts.length === 2) return await dash.listConnections(res);
            if (method === "DELETE" && parts.length === 3)
              return await dash.deleteConnection(decodeURIComponent(parts[2]), res);
          }
          if (parts[1] === "usb") {
            if (method === "GET" && parts.length === 2) return await dash.listUsb(res);
            if (method === "POST" && parts[2] === "backup" && parts.length === 3)
              return await dash.usbBackup(await readJson(), res);
            if (method === "POST" && parts[2] === "sync" && parts.length === 3)
              return await dash.usbSync(await readJson(), res);
          }
          if (parts[1] === "keys") {
            if (method === "GET" && parts.length === 2) return await dash.listApiKeys(res);
            if (method === "POST" && parts.length === 2)
              return await dash.createApiKey(await readJson(), res);
            if (method === "DELETE" && parts.length === 3)
              return await dash.revokeApiKey(decodeURIComponent(parts[2]), res);
          }
          send(res, 404, { error: "not found" });
          return;
        }

        // ── dapp-facing API (unchanged contract) ──────────────────────
        if (method === "GET" && pathname === "/grants") {
          send(res, 200, { grants: listGrants() });
          return;
        }

        if (req.method === "DELETE" && req.url === "/grants") {
          const revoked = revokeAll();
          console.log(`✓ revoked ${revoked} session grant(s)`);
          send(res, 200, { revoked });
          return;
        }

        if (req.method === "POST" && req.url === "/secret") {
          // loopback only
          const remote = req.socket.remoteAddress ?? "";
          if (!/^127\.0\.0\.1$|^::1$|^::ffff:127\.0\.0\.1$/.test(remote)) {
            send(res, 403, { error: "loopback connections only" });
            return;
          }

          if (licenseEnforcementEnabled() && !(await isLicensed())) {
            send(res, 403, { error: "license_required" });
            return;
          }

          let body: SecretRequest;
          try {
            body = JSON.parse(await readBody(req)) as SecretRequest;
          } catch {
            send(res, 400, { error: "invalid JSON body" });
            return;
          }

          const { project, keys } = body;
          if (!project || !Array.isArray(keys) || keys.length === 0) {
            send(res, 400, { error: 'expected {"project": "...", "keys": ["..."]}' });
            return;
          }
          if (keys.length > 50) {
            send(res, 400, { error: "too many keys requested" });
            return;
          }

          const vault = await loadVault();
          let proj;
          try {
            proj = assertProject(vault, project);
          } catch {
            send(res, 404, { error: `project not found: ${project}` });
            return;
          }

          const missing = keys.filter((k) => !(k in proj.vars));
          if (missing.length > 0) {
            send(res, 404, { error: `vars not found: ${missing.join(", ")}` });
            return;
          }

          // ── API key auth (skips Touch ID — meant for AI agents/scripts) ──
          const authHeader = req.headers.authorization;
          if (authHeader?.startsWith("Bearer ")) {
            const { findValidApiKey, apiKeyHasAccess } = await import("../core/apikeys.js");
            const record = findValidApiKey(vault, authHeader.slice(7).trim());
            if (!record) {
              send(res, 401, { error: "invalid or expired API key" });
              return;
            }
            if (!apiKeyHasAccess(record, project)) {
              send(res, 403, {
                error: `API key "${record.name}" has no access to project "${project}"`,
              });
              return;
            }
            const values: Record<string, string> = {};
            for (const k of keys) values[k] = proj.vars[k].value;
            console.log(
              `✓ served ${keys.length} var(s) from "${project}" to API key "${record.name}" (${record.id})`,
            );
            send(res, 200, values);
            return;
          }

          const clientPort = req.socket.remotePort ?? 0;
          const requester = await identifyPeer(clientPort);

          const ttl =
            typeof body.ttl === "number" && body.ttl > 0
              ? Math.min(Math.floor(body.ttl), MAX_TTL_SECONDS)
              : 0;

          if (ttl > 0) {
            const grant = findGrant(requester.appId, project);
            if (grant) {
              const values: Record<string, string> = {};
              for (const k of keys) values[k] = proj.vars[k].value;
              console.log(
                `✓ served ${keys.length} var(s) from "${project}" to ${requester.display} via session grant (${grant.expiresAt - Date.now()}ms left)`,
              );
              send(res, 200, values);
              return;
            }
          }

          try {
            await enqueueAuth(() =>
              authenticate(
                `abracadabra: ${requester.display} requests ${keys.join(", ")} from "${project}"`,
              ),
            );
          } catch {
            send(res, 403, { error: "biometric authentication denied" });
            return;
          }

          if (ttl > 0) {
            issueGrant(requester.appId, project, ttl);
            console.log(
              `✓ issued session grant for "${project}" to ${requester.display} (ttl ${ttl}s)`,
            );
          }

          const values: Record<string, string> = {};
          for (const k of keys) values[k] = proj.vars[k].value;
          console.log(`✓ served ${keys.length} var(s) from "${project}" to ${requester.display}`);
          send(res, 200, values);
          return;
        }

        // ── web dash static files ─────────────────────────────────────
        if (method === "GET" && dash.serveStatic(res, pathname)) return;

        send(res, 404, { error: "not found" });
  } catch (err) {
    send(res, 500, {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

export async function startServer(port = 7331, open = false): Promise<void> {
  const server = createApiServer();

  await new Promise<void>((resolve) => {
    server.listen(port, "127.0.0.1", () => resolve());
  });
  console.log(`✦ abracadabra API listening on http://127.0.0.1:${port}`);
  {
    const vault = await loadVault();
    if (!vault.passkeys?.length) {
      console.log("\n  ✦ web dash: no passkey registered yet.");
      console.log("    Open the dash in your browser and follow the passkey setup —");
      console.log("    it will fire a Touch ID prompt, then save a biometric passkey");
      console.log("    (Chrome can sync it to your Google Password Manager).\n");
    }
  }

  if (dash.webDistMissing()) {
    console.log("⚠ web dash not built — run: npm run web:build");
  } else {
    console.log(`  ✦ dash:    http://127.0.0.1:${port}/`);
    if (open) {
      const { execFile } = await import("node:child_process");
      execFile("open", [`http://127.0.0.1:${port}/`]);
    }
  }
  console.log('  POST   /secret   {"project": "name", "keys": ["KEY"], "ttl"?: seconds}');
  console.log("  GET    /grants   list active session grants");
  console.log("  DELETE /grants   revoke all session grants");
}
