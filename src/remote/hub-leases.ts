import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";
import { isUuid } from "../sync/identity.js";
import type { LeaseBinding } from "./lease.js";
import {
  assertPrivatePath,
  ensureRemoteDir,
  remoteDir,
  writePrivateFile,
} from "./private-fs.js";

/**
 * Hub-side metadata for leases this vault issued (PR 7).
 * No secret values — leaseId / peer / project / binding / times only.
 * Files: `<abraDir>/remote/hub-leases/<leaseId>.json` (0600).
 */

export const HUB_LEASES_DIRNAME = "hub-leases";

/** Renew when remaining life is under this window (default 24h). */
export const LEASE_RENEW_WITHIN_MS = 24 * 60 * 60 * 1000;

export interface HubLeaseRecord {
  v: 1;
  leaseId: string;
  /** Sync peer name (display). */
  peerName: string;
  /** Sync peer identity id. */
  peerSyncId: string;
  /** Receiver device-key id. */
  peerDeviceId: string;
  project: string;
  binding: LeaseBinding;
  issuedAt: number;
  expiresAt: number;
  ttlSeconds: number;
}

export function hubLeasesDir(base: string = abraDir()): string {
  return path.join(remoteDir(base), HUB_LEASES_DIRNAME);
}

function safeLeaseFileName(leaseId: string): string {
  if (!isUuid(leaseId)) throw new Error("invalid lease id");
  return `${leaseId.toLowerCase()}.json`;
}

export function hubLeaseFilePath(leaseId: string, base: string = abraDir()): string {
  return path.join(hubLeasesDir(base), safeLeaseFileName(leaseId));
}

function ensureHubLeasesDir(base: string): void {
  ensureRemoteDir(base);
  const dir = hubLeasesDir(base);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertPrivatePath(dir, { expectDir: true });
}

function parseRecord(raw: unknown): HubLeaseRecord | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const e = raw as Record<string, unknown>;
  if (e.v !== 1) return null;
  if (!isUuid(e.leaseId) || !isUuid(e.peerSyncId) || !isUuid(e.peerDeviceId)) return null;
  if (typeof e.peerName !== "string" || !e.peerName) return null;
  if (typeof e.project !== "string" || !e.project.trim()) return null;
  const b = e.binding as Record<string, unknown> | undefined;
  if (
    !b ||
    typeof b.exe !== "string" ||
    typeof b.dev !== "number" ||
    typeof b.ino !== "number"
  ) {
    return null;
  }
  if (
    typeof e.issuedAt !== "number" ||
    typeof e.expiresAt !== "number" ||
    typeof e.ttlSeconds !== "number"
  ) {
    return null;
  }
  return {
    v: 1,
    leaseId: e.leaseId as string,
    peerName: e.peerName as string,
    peerSyncId: e.peerSyncId as string,
    peerDeviceId: e.peerDeviceId as string,
    project: (e.project as string).trim(),
    binding: { exe: b.exe as string, dev: b.dev as number, ino: b.ino as number },
    issuedAt: e.issuedAt as number,
    expiresAt: e.expiresAt as number,
    ttlSeconds: e.ttlSeconds as number,
  };
}

export function listHubLeaseRecords(base: string = abraDir()): HubLeaseRecord[] {
  const dir = hubLeasesDir(base);
  if (!fs.existsSync(dir)) return [];
  try {
    assertPrivatePath(dir, { expectDir: true });
  } catch {
    return [];
  }
  const out: HubLeaseRecord[] = [];
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    try {
      const file = path.join(dir, name);
      assertPrivatePath(file, { expectDir: false });
      const rec = parseRecord(JSON.parse(fs.readFileSync(file, "utf8")));
      if (rec) out.push(rec);
    } catch {
      /* skip corrupt */
    }
  }
  return out.sort((a, b) => a.expiresAt - b.expiresAt);
}

export function getHubLeaseRecord(
  leaseId: string,
  base: string = abraDir(),
): HubLeaseRecord | null {
  const file = hubLeaseFilePath(leaseId, base);
  if (!fs.existsSync(file)) return null;
  try {
    assertPrivatePath(file, { expectDir: false });
    return parseRecord(JSON.parse(fs.readFileSync(file, "utf8")));
  } catch {
    return null;
  }
}

export function putHubLeaseRecord(record: HubLeaseRecord, base: string = abraDir()): void {
  ensureHubLeasesDir(base);
  const file = hubLeaseFilePath(record.leaseId, base);
  writePrivateFile(file, `${JSON.stringify(record)}\n`);
}

export function deleteHubLeaseRecord(leaseId: string, base: string = abraDir()): boolean {
  const file = hubLeaseFilePath(leaseId, base);
  if (!fs.existsSync(file)) return false;
  fs.rmSync(file, { force: true });
  return true;
}

/** Drop hub records for a peer (by sync id and/or device id). Returns count removed. */
export function deleteHubLeaseRecordsForPeer(
  opts: { peerSyncId?: string; peerDeviceId?: string; peerName?: string },
  base: string = abraDir(),
): number {
  let n = 0;
  for (const rec of listHubLeaseRecords(base)) {
    const match =
      (opts.peerSyncId !== undefined && rec.peerSyncId === opts.peerSyncId) ||
      (opts.peerDeviceId !== undefined && rec.peerDeviceId === opts.peerDeviceId) ||
      (opts.peerName !== undefined && rec.peerName === opts.peerName);
    if (match && deleteHubLeaseRecord(rec.leaseId, base)) n++;
  }
  return n;
}

/** Leases whose remaining life is under `withinMs` (default 24h). */
export function listHubLeasesNeedingRenew(
  base: string = abraDir(),
  opts: { now?: number; withinMs?: number } = {},
): HubLeaseRecord[] {
  const now = opts.now ?? Date.now();
  const within = opts.withinMs ?? LEASE_RENEW_WITHIN_MS;
  return listHubLeaseRecords(base).filter((r) => {
    if (r.expiresAt <= now) return true;
    return r.expiresAt - now <= within;
  });
}
