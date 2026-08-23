import http from "node:http";
import { loadVault, assertProject } from "../core/vault.js";
import { authenticate } from "../auth/touchid.js";
import { identifyPeer } from "./identify.js";
import { findGrant, issueGrant, listGrants, revokeAll } from "./grants.js";
import { send } from "./http-utils.js";
import * as dash from "./dash.js";

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

export async function startServer(port = 7331, open = false): Promise<void> {
  const server = http.createServer((req, res) => {
    void (async () => {
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
    })();
  });

  await new Promise<void>((resolve) => {
    server.listen(port, "127.0.0.1", () => resolve());
  });
  console.log(`✦ abracadabra API listening on http://127.0.0.1:${port}`);
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
