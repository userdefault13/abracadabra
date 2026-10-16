import fs from "node:fs";
import path from "node:path";
import type { SyncPeerRole, Vault } from "./vault.js";
import { createEphemeralTls, fingerprintOfPem, type EphemeralTls } from "./tls-ephemeral.js";
import { isUuid } from "../sync/identity.js";
import { parseEnvelope, type EnvelopeTrust, type SealedEnvelope } from "../sync/envelope.js";

/**
 * On-disk state of the receiver inbox, under `<abraDir>/sync-inbox/` (0700):
 *
 *   queue/<bundleId>   still-sealed envelopes awaiting apply (0600, bounded)
 *   seen.json          replay cache: bundleId → createdAt (bounded, non-secret)
 *   anchors.json       non-secret mirror of inbox settings + pinned SOURCE public
 *                      keys, so a LOCKED agent can verify signatures before
 *                      queueing. Never trusted for apply — apply re-verifies
 *                      against the vault.
 *   tls-key.pem / tls-cert.pem  stable self-signed listener cert (transport only)
 *
 * Nothing here is ever decrypted vault content.
 */

export const INBOX_DIRNAME = "sync-inbox";
export const MAX_QUEUED_BUNDLES = 64;
export const MAX_QUEUE_BYTES = 64 * 1024 * 1024;
export const REPLAY_RETENTION_MS = 24 * 60 * 60_000;
export const MAX_REPLAY_ENTRIES = 4096;
export const INBOX_DEFAULT_PORT = 7333;

const isPosix = process.platform !== "win32";

export function syncInboxDir(base: string): string {
  return path.join(base, INBOX_DIRNAME);
}

/** mkdir -p with 0700; refuses a symlinked dir; tightens mode on POSIX. */
export function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`refusing non-directory inbox path: ${dir}`);
  if (isPosix && (st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}

/** Atomic 0600 write (tmp + rename). */
export function writePrivateFile(file: string, data: string): void {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

// ───────────────────────────── queue ─────────────────────────────

export interface QueuedBundle {
  v: 1;
  receivedAt: number;
  remote?: string;
  /** Which pinned keys the signature was checked against at receive time. */
  verifiedWith: "vault" | "mirror";
  envelope: SealedEnvelope;
}

export class InboxFullError extends Error {
  constructor() {
    super("sync inbox is full — apply or reject queued bundles (abra sync inbox)");
    this.name = "InboxFullError";
  }
}

export class InboxQueue {
  readonly dir: string;

  constructor(
    private readonly base: string,
    private readonly limits: { maxCount: number; maxBytes: number } = {
      maxCount: MAX_QUEUED_BUNDLES,
      maxBytes: MAX_QUEUE_BYTES,
    },
  ) {
    this.dir = path.join(syncInboxDir(base), "queue");
  }

  private file(id: string): string {
    if (!isUuid(id)) throw new Error(`invalid bundle id ${JSON.stringify(String(id).slice(0, 64))}`);
    return path.join(this.dir, id.toLowerCase());
  }

  ids(): string[] {
    let names: string[];
    try {
      names = fs.readdirSync(this.dir);
    } catch {
      return [];
    }
    return names.filter((n) => isUuid(n)).sort();
  }

  has(id: string): boolean {
    return fs.existsSync(this.file(id));
  }

  private usage(): { count: number; bytes: number } {
    let bytes = 0;
    const ids = this.ids();
    for (const id of ids) {
      try {
        bytes += fs.statSync(this.file(id)).size;
      } catch {
        /* raced with delete */
      }
    }
    return { count: ids.length, bytes };
  }

  write(entry: QueuedBundle): void {
    const data = JSON.stringify(entry);
    const { count, bytes } = this.usage();
    if (count + 1 > this.limits.maxCount || bytes + Buffer.byteLength(data) > this.limits.maxBytes) {
      throw new InboxFullError();
    }
    ensurePrivateDir(syncInboxDir(this.base));
    ensurePrivateDir(this.dir);
    const file = this.file(entry.envelope.bundleId);
    if (fs.existsSync(file)) throw new Error("bundle already queued");
    writePrivateFile(file, data);
  }

  read(id: string): QueuedBundle {
    const raw = JSON.parse(fs.readFileSync(this.file(id), "utf8")) as Record<string, unknown>;
    const envelope = parseEnvelope(raw.envelope);
    if (envelope.bundleId.toLowerCase() !== id.toLowerCase()) throw new Error("queued file name does not match its bundle id");
    return {
      v: 1,
      receivedAt: typeof raw.receivedAt === "number" ? raw.receivedAt : 0,
      ...(typeof raw.remote === "string" ? { remote: raw.remote } : {}),
      verifiedWith: raw.verifiedWith === "vault" ? "vault" : "mirror",
      envelope,
    };
  }

  remove(id: string): boolean {
    const file = this.file(id);
    if (!fs.existsSync(file)) return false;
    fs.rmSync(file, { force: true });
    return true;
  }
}

// ───────────────────────────── replay cache ─────────────────────────────

export class ReplayCache {
  readonly file: string;

  constructor(
    private readonly base: string,
    private readonly opts: { retentionMs: number; maxEntries: number } = {
      retentionMs: REPLAY_RETENTION_MS,
      maxEntries: MAX_REPLAY_ENTRIES,
    },
  ) {
    this.file = path.join(syncInboxDir(base), "seen.json");
  }

  private load(): Map<string, number> {
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, "utf8")) as { seen?: Record<string, unknown> };
      const out = new Map<string, number>();
      for (const [id, at] of Object.entries(raw.seen ?? {})) {
        if (isUuid(id) && typeof at === "number") out.set(id.toLowerCase(), at);
      }
      return out;
    } catch {
      return new Map();
    }
  }

  has(id: string): boolean {
    return this.load().has(id.toLowerCase());
  }

  /** Record `id`, pruning entries older than the retention window and capping the size. */
  add(id: string, createdAt: number, now: number): void {
    const seen = this.load();
    seen.set(id.toLowerCase(), createdAt);
    const kept = [...seen.entries()]
      .filter(([, at]) => at >= now - this.opts.retentionMs)
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.opts.maxEntries);
    ensurePrivateDir(syncInboxDir(this.base));
    writePrivateFile(this.file, JSON.stringify({ v: 1, seen: Object.fromEntries(kept) }));
  }
}

// ───────────────────────────── trust mirror ─────────────────────────────

export interface InboxAnchors {
  v: 1;
  enabled: boolean;
  bind: string | null;
  port: number;
  me: { id: string } | null;
  /** Paired SOURCE peers only (public signing keys). */
  sources: Record<string, { name: string; ed25519: string }>;
}

export function anchorsFile(base: string): string {
  return path.join(syncInboxDir(base), "anchors.json");
}

/** Null when the inbox was never configured on this vault. */
export function anchorsFromVault(vault: Vault): InboxAnchors | null {
  const s = vault.syncInbox;
  if (!s) return null;
  const sources: InboxAnchors["sources"] = {};
  for (const [id, p] of Object.entries(vault.syncPeers ?? {})) {
    if (p.role === "source") sources[id] = { name: p.name, ed25519: p.ed25519 };
  }
  return {
    v: 1,
    enabled: s.enabled === true,
    bind: s.bind ?? null,
    port: s.port,
    me: vault.syncIdentity ? { id: vault.syncIdentity.id } : null,
    sources,
  };
}

export function readAnchors(base: string): InboxAnchors | null {
  try {
    const raw = JSON.parse(fs.readFileSync(anchorsFile(base), "utf8")) as InboxAnchors;
    if (raw?.v !== 1 || typeof raw.enabled !== "boolean" || typeof raw.port !== "number") return null;
    if (raw.bind !== null && typeof raw.bind !== "string") return null;
    if (raw.me !== null && !isUuid(raw.me?.id)) return null;
    const sources: InboxAnchors["sources"] = {};
    for (const [id, p] of Object.entries(raw.sources ?? {})) {
      if (isUuid(id) && typeof p?.name === "string" && typeof p?.ed25519 === "string") {
        sources[id] = { name: p.name, ed25519: p.ed25519 };
      }
    }
    return { v: 1, enabled: raw.enabled, bind: raw.bind, port: raw.port, me: raw.me ? { id: raw.me.id } : null, sources };
  } catch {
    return null;
  }
}

export function writeAnchors(base: string, anchors: InboxAnchors | null): void {
  if (!anchors) {
    fs.rmSync(anchorsFile(base), { force: true });
    return;
  }
  ensurePrivateDir(syncInboxDir(base));
  writePrivateFile(anchorsFile(base), JSON.stringify(anchors, null, 2));
}

/** Keep the mirror in step with the vault; a vault without inbox settings removes it. */
export function syncAnchorsFromVault(base: string, vault: Vault): InboxAnchors | null {
  const anchors = anchorsFromVault(vault);
  if (anchors || fs.existsSync(anchorsFile(base))) writeAnchors(base, anchors);
  return anchors;
}

export function trustFromAnchors(anchors: InboxAnchors | null): EnvelopeTrust | null {
  if (!anchors?.me) return null;
  const peers: EnvelopeTrust["peers"] = {};
  for (const [id, p] of Object.entries(anchors.sources)) {
    peers[id] = { name: p.name, ed25519: p.ed25519, role: "source" as SyncPeerRole };
  }
  return { myId: anchors.me.id, peers };
}

// ───────────────────────────── listener TLS ─────────────────────────────

/**
 * Stable self-signed listener cert, created once per device (openssl). It only
 * provides transport privacy for envelope metadata; authenticity comes from the
 * envelope signature, so senders need not pin it.
 */
export function loadOrCreateInboxTls(
  base: string,
  create: (commonName: string) => EphemeralTls = (cn) => createEphemeralTls(cn, { days: 3650 }),
): EphemeralTls {
  const dir = syncInboxDir(base);
  const keyFile = path.join(dir, "tls-key.pem");
  const certFile = path.join(dir, "tls-cert.pem");
  try {
    const key = fs.readFileSync(keyFile, "utf8");
    const cert = fs.readFileSync(certFile, "utf8");
    return { key, cert, fingerprint: fingerprintOfPem(cert) };
  } catch {
    ensurePrivateDir(dir);
    const tls = create("abra-sync-inbox");
    writePrivateFile(keyFile, tls.key);
    writePrivateFile(certFile, tls.cert);
    return tls;
  }
}
