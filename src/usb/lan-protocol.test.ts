import { describe, it, expect, beforeEach, afterEach } from "vitest";
import https from "node:https";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createEphemeralTls } from "../core/tls-ephemeral.js";
import { sealBundle, openBundle } from "../core/backup.js";
import { encryptVault, decryptEnvelope } from "../core/vault.js";
import type { Vault } from "../core/vault.js";

/**
 * Lightweight protocol smoke test without Touch ID / vault I/O:
 * stand up an HTTPS server mimicking /lan/info, /lan/pull, /lan/push PIN gates.
 */
describe("LAN PIN protocol", () => {
  let tmp: string;
  let server: https.Server;
  let port: number;
  const pin = "482910";
  const pinBuf = Buffer.from(pin, "utf8");

  function timingSafePin(provided: string): boolean {
    const got = Buffer.from(provided.normalize("NFKC"), "utf8");
    if (got.length !== pinBuf.length) return false;
    return crypto.timingSafeEqual(pinBuf, got);
  }

  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "abra-lan-"));
    process.env.ABRA_DIR = tmp;
    const tls = createEphemeralTls("lan-test");
    let failCount = 0;
    let locked = false;

    const masterKey = crypto.randomBytes(32);
    const vault: Vault = {
      version: 1,
      projects: { demo: { createdAt: 1, vars: { A: { value: "1", secret: true, updatedAt: 1 } } } },
    };
    const bundle = sealBundle(encryptVault(vault, masterKey), masterKey, pin);

    server = https.createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
      const url = new URL(req.url ?? "/", "https://127.0.0.1");
      const send = (status: number, body: unknown) => {
        const data = JSON.stringify(body);
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(data);
      };
      const auth = req.headers.authorization ?? "";
      const gotPin = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

      if (req.method === "GET" && url.pathname === "/lan/info") {
        send(200, { hostname: "test", port: 0, expiresAt: Date.now() + 60_000, fingerprint: tls.fingerprint });
        return;
      }
      if (locked) {
        send(429, { error: "locked" });
        return;
      }
      if (req.method === "POST" && url.pathname === "/lan/pull") {
        if (!timingSafePin(gotPin)) {
          failCount++;
          if (failCount >= 8) locked = true;
          send(401, { error: "invalid PIN" });
          return;
        }
        send(200, { bundle });
        return;
      }
      if (req.method === "POST" && url.pathname === "/lan/push") {
        if (!timingSafePin(gotPin)) {
          failCount++;
          send(401, { error: "invalid PIN" });
          return;
        }
        const chunks: Buffer[] = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { bundle?: typeof bundle };
          if (!body.bundle) {
            send(400, { error: "no bundle" });
            return;
          }
          try {
            openBundle(body.bundle, pin);
            send(200, { ok: true });
          } catch {
            send(400, { error: "bad bundle" });
          }
        });
        return;
      }
      send(404, { error: "not found" });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    port = (server.address() as { port: number }).port;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmp, { recursive: true, force: true });
    delete process.env.ABRA_DIR;
  });

  function request(
    method: string,
    pathname: string,
    headers?: Record<string, string>,
    body?: string,
  ): Promise<{ status: number; json: unknown }> {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: "127.0.0.1",
          port,
          path: pathname,
          method,
          headers,
          rejectUnauthorized: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            resolve({
              status: res.statusCode ?? 0,
              json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"),
            });
          });
        },
      );
      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
  }

  it("rejects wrong PIN on pull", async () => {
    const res = await request("POST", "/lan/pull", { Authorization: "Bearer 000000" }, "{}");
    expect(res.status).toBe(401);
  });

  it("pulls and opens bundle with correct PIN", async () => {
    const res = await request("POST", "/lan/pull", { Authorization: `Bearer ${pin}` }, "{}");
    expect(res.status).toBe(200);
    const bundle = (res.json as { bundle: Parameters<typeof openBundle>[0] }).bundle;
    const payload = openBundle(bundle, pin);
    const vault = decryptEnvelope(payload.vaultEnc, Buffer.from(payload.masterKey, "base64"));
    expect(vault.projects.demo.vars.A.value).toBe("1");
  });

  it("accepts push of sealed bundle", async () => {
    const pull = await request("POST", "/lan/pull", { Authorization: `Bearer ${pin}` }, "{}");
    const bundle = (pull.json as { bundle: unknown }).bundle;
    const body = JSON.stringify({ bundle });
    const res = await request(
      "POST",
      "/lan/push",
      {
        Authorization: `Bearer ${pin}`,
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
      },
      body,
    );
    expect(res.status).toBe(200);
  });
});
