import https from "node:https";
import { createHash } from "node:crypto";
import type { TLSSocket } from "node:tls";
import type { BackupBundle } from "../core/backup.js";
import { openBundle, sealBundle } from "../core/backup.js";
import {
  loadVault,
  saveVault,
  encryptVault,
  decryptEnvelope,
} from "../core/vault.js";
import type { Vault } from "../core/vault.js";
import { getMasterKey, authenticate } from "../platform/index.js";
import {
  threeWayMerge,
  loadSyncState,
  saveSyncState,
  type Resolutions,
} from "../core/sync.js";
import { fingerprintsMatch } from "../core/tls-ephemeral.js";
import { LAN_MDNS_TYPE, LAN_DEFAULT_PORT } from "./lan-host.js";

export interface LanPeer {
  name: string;
  host: string;
  port: number;
  fingerprint?: string;
  hostname?: string;
}

export interface ConflictInfo {
  scope: string;
  key: string;
  newest: "ours" | "theirs";
  ours?: string;
  theirs?: string;
}

export interface LanSyncPreview {
  report: string[];
  conflicts: ConflictInfo[];
  needsResolution: boolean;
}

function maskValue(v: string): string {
  if (v.length <= 4) return "••••";
  return `${v.slice(0, 2)}${"•".repeat(6)}${v.slice(-2)}`;
}

function toConflictInfo(c: {
  scope: string;
  key: string;
  ours?: { value: string; updatedAt: number };
  theirs?: { value: string; updatedAt: number };
}): ConflictInfo {
  const ours = c.ours === undefined ? "(deleted)" : maskValue(c.ours.value);
  const theirs = c.theirs === undefined ? "(deleted)" : maskValue(c.theirs.value);
  const newest: "ours" | "theirs" =
    c.ours && c.theirs
      ? c.ours.updatedAt >= c.theirs.updatedAt
        ? "ours"
        : "theirs"
      : c.theirs === undefined
        ? "ours"
        : "theirs";
  return { scope: c.scope, key: c.key, newest, ours, theirs };
}

export function parseHostPort(target: string): { host: string; port: number } {
  const trimmed = target.trim();
  if (trimmed.includes("://")) {
    const u = new URL(trimmed);
    return { host: u.hostname, port: Number(u.port) || LAN_DEFAULT_PORT };
  }
  const idx = trimmed.lastIndexOf(":");
  if (idx === -1) return { host: trimmed, port: LAN_DEFAULT_PORT };
  const host = trimmed.slice(0, idx).replace(/^\[/, "").replace(/\]$/, "");
  const port = Number(trimmed.slice(idx + 1));
  if (!Number.isInteger(port) || port < 1) throw new Error(`Invalid host:port: ${target}`);
  return { host, port };
}

function peerFingerprintFromSocket(socket: TLSSocket): string {
  try {
    const cert = socket.getPeerCertificate(true);
    if (cert?.raw) {
      const hex = createHash("sha256").update(cert.raw as Buffer).digest("hex");
      return (hex.match(/.{2}/g) ?? []).slice(0, 8).join(":").toUpperCase();
    }
    if (typeof cert?.fingerprint256 === "string") {
      return cert.fingerprint256.split(":").slice(0, 8).join(":").toUpperCase();
    }
  } catch {
    /* ignore */
  }
  return "";
}

function httpsRequest(opts: {
  host: string;
  port: number;
  path: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  expectedFingerprint?: string;
}): Promise<{ status: number; json: unknown; peerFingerprint: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: opts.host,
        port: opts.port,
        path: opts.path,
        method: opts.method,
        headers: opts.headers,
        rejectUnauthorized: false,
        timeout: 30_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const peerFp = peerFingerprintFromSocket(res.socket as TLSSocket);
          if (opts.expectedFingerprint) {
            if (!peerFp) {
              reject(new Error("TLS fingerprint unavailable — refusing unauthenticated peer"));
              return;
            }
            if (!fingerprintsMatch(opts.expectedFingerprint, peerFp)) {
              reject(new Error(`TLS fingerprint mismatch (got ${peerFp})`));
              return;
            }
          }
          const text = Buffer.concat(chunks).toString("utf8");
          let json: unknown = {};
          try {
            json = text ? JSON.parse(text) : {};
          } catch {
            json = { error: text };
          }
          resolve({ status: res.statusCode ?? 0, json, peerFingerprint: peerFp });
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("connection timed out"));
    });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

export async function fetchLanInfo(
  target: string,
  expectedFingerprint?: string,
): Promise<{ hostname: string; port: number; expiresAt: number; fingerprint: string }> {
  const { host, port } = parseHostPort(target);
  const res = await httpsRequest({
    host,
    port,
    path: "/lan/info",
    method: "GET",
    expectedFingerprint,
  });
  if (res.status !== 200) {
    throw new Error(`LAN info failed (${res.status}): ${JSON.stringify(res.json)}`);
  }
  return res.json as {
    hostname: string;
    port: number;
    expiresAt: number;
    fingerprint: string;
  };
}

async function pullBundle(
  target: string,
  pin: string,
  expectedFingerprint?: string,
): Promise<{ bundle: BackupBundle; peerFingerprint: string }> {
  const { host, port } = parseHostPort(target);
  const res = await httpsRequest({
    host,
    port,
    path: "/lan/pull",
    method: "POST",
    headers: {
      Authorization: `Bearer ${pin}`,
      "Content-Type": "application/json",
      "Content-Length": "2",
    },
    body: "{}",
    expectedFingerprint,
  });
  if (res.status === 401) throw new Error("invalid PIN");
  if (res.status !== 200) {
    throw new Error(`LAN pull failed (${res.status}): ${JSON.stringify(res.json)}`);
  }
  const bundle = (res.json as { bundle?: BackupBundle }).bundle;
  if (!bundle) throw new Error("LAN pull returned no bundle");
  return { bundle, peerFingerprint: res.peerFingerprint };
}

async function pushBundle(
  target: string,
  pin: string,
  bundle: BackupBundle,
  expectedFingerprint?: string,
): Promise<void> {
  const { host, port } = parseHostPort(target);
  const body = JSON.stringify({ bundle });
  const res = await httpsRequest({
    host,
    port,
    path: "/lan/push",
    method: "POST",
    headers: {
      Authorization: `Bearer ${pin}`,
      "Content-Type": "application/json",
      "Content-Length": String(Buffer.byteLength(body)),
    },
    body,
    expectedFingerprint,
  });
  if (res.status === 401) throw new Error("invalid PIN");
  if (res.status !== 200) {
    throw new Error(`LAN push failed (${res.status}): ${JSON.stringify(res.json)}`);
  }
}

function openRemoteVault(bundle: BackupBundle, pin: string): Vault {
  const payload = openBundle(bundle, pin);
  return decryptEnvelope(payload.vaultEnc, Buffer.from(payload.masterKey, "base64"));
}

export class LanConflictError extends Error {
  constructor(public conflicts: ConflictInfo[]) {
    super("sync conflicts need resolution");
  }
}

export async function previewLanSync(
  target: string,
  pin: string,
  expectedFingerprint?: string,
): Promise<LanSyncPreview> {
  const { bundle } = await pullBundle(target, pin, expectedFingerprint);
  let remote: Vault;
  try {
    remote = openRemoteVault(bundle, pin);
  } catch {
    throw new Error("Wrong PIN for sealed bundle");
  }
  const local = await loadVault();
  const base = (await loadSyncState())?.base ?? null;
  const { conflicts, report } = threeWayMerge(local, remote, base, new Map(), "LAN peer");
  return {
    report,
    conflicts: conflicts.map(toConflictInfo),
    needsResolution: conflicts.length > 0,
  };
}

export async function applyLanSync(
  target: string,
  pin: string,
  force?: "ours" | "theirs",
  expectedFingerprint?: string,
): Promise<{ changed: boolean; report: string[] }> {
  const { bundle } = await pullBundle(target, pin, expectedFingerprint);
  let remote: Vault;
  try {
    remote = openRemoteVault(bundle, pin);
  } catch {
    throw new Error("Wrong PIN for sealed bundle");
  }
  const local = await loadVault();
  const base = (await loadSyncState())?.base ?? null;
  const resolutions: Resolutions = new Map();
  if (force) {
    const probe = threeWayMerge(local, remote, base, new Map(), "LAN peer");
    for (const c of probe.conflicts) {
      resolutions.set(`${c.scope}/${c.key}`, force === "theirs" ? c.theirs : c.ours);
    }
  }
  const { merged, conflicts, report } = threeWayMerge(
    local,
    remote,
    base,
    resolutions,
    "LAN peer",
  );
  if (conflicts.length > 0 && !force) throw new LanConflictError(conflicts.map(toConflictInfo));

  if (report.length === 0) {
    await saveSyncState(local);
    const masterKey = await getMasterKey();
    const out = sealBundle(encryptVault(local, masterKey), masterKey, pin);
    await pushBundle(target, pin, out, expectedFingerprint);
    return { changed: false, report: [] };
  }

  await authenticate("abracadabra: sync vault over LAN");
  await saveVault(merged);
  const masterKey = await getMasterKey();
  const out = sealBundle(encryptVault(merged, masterKey), masterKey, pin);
  await pushBundle(target, pin, out, expectedFingerprint);
  await saveSyncState(merged);
  return { changed: true, report };
}

/** Browse mDNS for LAN sync hosts (waits briefly for announcements). */
export async function browseLanPeers(timeoutMs = 2500): Promise<LanPeer[]> {
  const { Bonjour } = await import("bonjour-service");
  const bonjour = new Bonjour();
  const found = new Map<string, LanPeer>();
  return new Promise((resolve) => {
    const browser = bonjour.find({ type: LAN_MDNS_TYPE }, (service) => {
      const host =
        (service.referer as { address?: string } | undefined)?.address ||
        service.host?.replace(/\.$/, "") ||
        "";
      if (!host || !service.port) return;
      const key = `${host}:${service.port}`;
      const txt = (service.txt ?? {}) as Record<string, string>;
      found.set(key, {
        name: service.name,
        host,
        port: service.port,
        fingerprint: txt.fingerprint,
        hostname: txt.hostname,
      });
    });
    setTimeout(() => {
      try {
        browser.stop();
        bonjour.destroy();
      } catch {
        /* ignore */
      }
      resolve([...found.values()]);
    }, timeoutMs);
  });
}
