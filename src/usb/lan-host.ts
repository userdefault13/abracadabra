import https from "node:https";
import http from "node:http";
import crypto from "node:crypto";
import os from "node:os";
import type { Server as HttpsServer } from "node:https";
import { sealBundle, openBundle } from "../core/backup.js";
import type { BackupBundle } from "../core/backup.js";
import { loadVault, saveVault, encryptVault, decryptEnvelope } from "../core/vault.js";
import { getMasterKey, authenticate } from "../platform/index.js";
import { saveSyncState } from "../core/sync.js";
import { createEphemeralTls } from "../core/tls-ephemeral.js";

export const LAN_MDNS_TYPE = "abracadabra-sync";
export const LAN_DEFAULT_PORT = 7332;
export const LAN_DEFAULT_TTL_MS = 10 * 60 * 1000;

export interface LanHostInfo {
  pin: string;
  port: number;
  addresses: string[];
  fingerprint: string;
  hostname: string;
  expiresAt: number;
}

export interface LanHostHandle extends LanHostInfo {
  stop: () => Promise<void>;
}

interface ActiveHost {
  server: HttpsServer;
  pin: string;
  pinBuf: Buffer;
  fingerprint: string;
  port: number;
  expiresAt: number;
  failCount: number;
  locked: boolean;
  pulled: boolean;
  stopTimer?: ReturnType<typeof setTimeout>;
  bonjour?: { unpublishAll: (cb?: () => void) => void; destroy: () => void };
  stopPromise?: Promise<void>;
}

let active: ActiveHost | null = null;

function privateAddresses(): string[] {
  const nets = os.networkInterfaces();
  const out: string[] = [];
  for (const entries of Object.values(nets)) {
    if (!entries) continue;
    for (const e of entries) {
      if (e.internal || e.family !== "IPv4") continue;
      out.push(e.address);
    }
  }
  return out;
}

function generatePin(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

function timingSafePin(expected: Buffer, provided: string): boolean {
  const got = Buffer.from(provided.normalize("NFKC"), "utf8");
  if (got.length !== expected.length) {
    crypto.timingSafeEqual(expected, expected);
    return false;
  }
  return crypto.timingSafeEqual(expected, got);
}

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 8 * 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(data),
  });
  res.end(data);
}

function extractPin(req: http.IncomingMessage): string {
  const auth = req.headers.authorization ?? "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return "";
}

async function buildSealedBundle(pin: string): Promise<BackupBundle> {
  const vault = await loadVault();
  const masterKey = await getMasterKey();
  return sealBundle(encryptVault(vault, masterKey), masterKey, pin);
}

export function getLanHostStatus(): LanHostInfo | null {
  if (!active) return null;
  if (Date.now() > active.expiresAt) return null;
  return {
    pin: active.pin,
    port: active.port,
    addresses: privateAddresses(),
    fingerprint: active.fingerprint,
    hostname: os.hostname(),
    expiresAt: active.expiresAt,
  };
}

export async function stopLanHost(): Promise<void> {
  const cur = active;
  active = null;
  if (!cur) return;
  if (cur.stopTimer) clearTimeout(cur.stopTimer);
  await new Promise<void>((resolve) => {
    cur.bonjour?.unpublishAll(() => {
      try {
        cur.bonjour?.destroy();
      } catch {
        /* ignore */
      }
      resolve();
    });
    if (!cur.bonjour) resolve();
  });
  await new Promise<void>((resolve) => {
    cur.server.close(() => resolve());
  });
}

export async function startLanHost(opts: {
  port?: number;
  ttlMs?: number;
  advertise?: boolean;
}): Promise<LanHostHandle> {
  if (active) await stopLanHost();

  await authenticate("abracadabra: start LAN vault sync host");

  const port = opts.port ?? LAN_DEFAULT_PORT;
  const ttlMs = opts.ttlMs ?? LAN_DEFAULT_TTL_MS;
  const pin = generatePin();
  const tls = createEphemeralTls(os.hostname());
  const expiresAt = Date.now() + ttlMs;

  const state: ActiveHost = {
    server: null as unknown as HttpsServer,
    pin,
    pinBuf: Buffer.from(pin, "utf8"),
    fingerprint: tls.fingerprint,
    port,
    expiresAt,
    failCount: 0,
    locked: false,
    pulled: false,
  };

  const server = https.createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
    void (async () => {
      try {
        if (!active || active !== state) {
          sendJson(res, 503, { error: "host stopped" });
          return;
        }
        if (Date.now() > state.expiresAt) {
          sendJson(res, 410, { error: "session expired" });
          void stopLanHost();
          return;
        }
        if (state.locked) {
          sendJson(res, 429, { error: "too many failed PIN attempts" });
          return;
        }

        const url = new URL(req.url ?? "/", `https://127.0.0.1:${port}`);
        const method = req.method ?? "GET";

        if (method === "GET" && url.pathname === "/lan/info") {
          sendJson(res, 200, {
            hostname: os.hostname(),
            port,
            expiresAt: state.expiresAt,
            fingerprint: state.fingerprint,
          });
          return;
        }

        if (method === "POST" && url.pathname === "/lan/pull") {
          const pinIn = extractPin(req);
          if (!timingSafePin(state.pinBuf, pinIn)) {
            state.failCount += 1;
            if (state.failCount >= 8) state.locked = true;
            sendJson(res, 401, { error: "invalid PIN" });
            return;
          }
          const bundle = await buildSealedBundle(pin);
          state.pulled = true;
          sendJson(res, 200, { bundle });
          return;
        }

        if (method === "POST" && url.pathname === "/lan/push") {
          const pinIn = extractPin(req);
          if (!timingSafePin(state.pinBuf, pinIn)) {
            state.failCount += 1;
            if (state.failCount >= 8) state.locked = true;
            sendJson(res, 401, { error: "invalid PIN" });
            return;
          }
          const body = (await readJson(req)) as { bundle?: BackupBundle };
          if (!body.bundle) {
            sendJson(res, 400, { error: "expected { bundle }" });
            return;
          }
          let payload;
          try {
            payload = openBundle(body.bundle, pin);
          } catch {
            sendJson(res, 400, { error: "invalid or unreadable bundle" });
            return;
          }
          await authenticate("abracadabra: apply LAN sync from peer");
          const peerMaster = Buffer.from(payload.masterKey, "base64");
          const vault = decryptEnvelope(payload.vaultEnc, peerMaster);
          // Re-encrypt under this machine's master key (same as USB sync apply).
          await saveVault(vault);
          await saveSyncState(vault);
          sendJson(res, 200, { ok: true });
          void stopLanHost();
          return;
        }

        sendJson(res, 404, { error: "not found" });
      } catch (err) {
        sendJson(res, 500, {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    })();
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(port, "0.0.0.0", () => resolve());
    server.on("error", reject);
  });
  state.server = server;
  active = state;

  state.stopTimer = setTimeout(() => {
    void stopLanHost();
  }, ttlMs);

  if (opts.advertise !== false) {
    try {
      const { Bonjour } = await import("bonjour-service");
      const bonjour = new Bonjour();
      bonjour.publish({
        name: `abra-${os.hostname()}`,
        type: LAN_MDNS_TYPE,
        port,
        txt: {
          fingerprint: tls.fingerprint,
          hostname: os.hostname(),
        },
      });
      state.bonjour = bonjour as unknown as ActiveHost["bonjour"];
    } catch {
      /* mDNS optional if publish fails */
    }
  }

  const info: LanHostInfo = {
    pin,
    port,
    addresses: privateAddresses(),
    fingerprint: tls.fingerprint,
    hostname: os.hostname(),
    expiresAt,
  };

  return {
    ...info,
    stop: () => stopLanHost(),
  };
}
