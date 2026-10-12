import https from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Project, Vault } from "../core/vault.js";
import { mergeScopedProjects, type ScopedMergeReport } from "../core/sync-scope.js";
import { decideAccept } from "./accept.js";
import {
  EnvelopeError,
  openEnvelope,
  parseEnvelope,
  trustFromVault,
  verifyEnvelope,
  type EnvelopeRejectReason,
  type SealedEnvelope,
} from "./envelope.js";
import {
  InboxFullError,
  InboxQueue,
  ReplayCache,
  readAnchors,
  trustFromAnchors,
} from "../core/sync-inbox-store.js";

/**
 * Receiver inbox: accepts sealed envelopes from paired SOURCE peers.
 *
 * - unlocked + matching auto rule → verify against the vault, decrypt,
 *   mergeScopedProjects (receiver-wins, never deletes), save → "applied"
 * - locked, or no auto rule → queue the still-sealed envelope → "queued"
 * - anything else → "rejected" (logged by reason only, never contents)
 *
 * The inbox only ever answers the HTTP request it was sent; it never
 * connects back to a peer.
 */

export const INBOX_PATH = "/v1/sync/inbox";
export const INBOX_MAX_BODY_BYTES = 8 * 1024 * 1024;
export const INBOX_RATE_LIMIT = { max: 30, windowMs: 60_000 };
const INBOX_DRAIN_CAP_BYTES = 64 * 1024;

export type InboxStatus = "applied" | "queued" | "rejected";

export interface InboxResponse {
  status: InboxStatus;
  reason?: string;
}

export type InboxRejectReason =
  | EnvelopeRejectReason
  | "not-configured"
  | "inbox-full"
  | "too-large"
  | "unsupported-media-type"
  | "rate-limited"
  | "not-found"
  | "method-not-allowed"
  | "internal";

/** HTTP status + coarse public reason (auth failures are not distinguished to the sender). */
const PUBLIC_REJECT: Record<InboxRejectReason, [number, string]> = {
  malformed: [400, "bad-request"],
  "decrypt-failed": [400, "bad-request"],
  "bad-projects": [400, "bad-projects"],
  "wrong-recipient": [403, "unauthorized"],
  "unknown-sender": [403, "unauthorized"],
  "sender-not-source": [403, "unauthorized"],
  "bad-signature": [403, "unauthorized"],
  stale: [403, "stale"],
  replay: [409, "replay"],
  "not-configured": [503, "not-configured"],
  "inbox-full": [507, "inbox-full"],
  "too-large": [413, "too-large"],
  "unsupported-media-type": [415, "unsupported-media-type"],
  "rate-limited": [429, "rate-limited"],
  "not-found": [404, "not-found"],
  "method-not-allowed": [405, "method-not-allowed"],
  internal: [500, "internal"],
};

export interface ProjectCounts {
  project: string;
  isNew: boolean;
  added: number;
  keptLocal: number;
}

export interface InboxOutcome {
  response: InboxResponse;
  httpStatus: number;
  /** Local-only detail for logs (never sent). */
  reason?: InboxRejectReason;
  bundleId?: string;
  peerName?: string;
  counts?: ProjectCounts[];
}

export function rejectOutcome(reason: InboxRejectReason, bundleId?: string): InboxOutcome {
  const [httpStatus, publicReason] = PUBLIC_REJECT[reason];
  return { response: { status: "rejected", reason: publicReason }, httpStatus, reason, bundleId };
}

/** Per-project counts from a scoped merge report — names and numbers only. */
export function countMerge(report: ScopedMergeReport, incoming: Record<string, Project>): ProjectCounts[] {
  return Object.keys(incoming)
    .sort()
    .map((project) => {
      const created = report.newProjects.find((p) => p.project === project);
      return {
        project,
        isNew: Boolean(created),
        added: created ? created.keys : report.added.filter((a) => a.project === project).length,
        keptLocal: report.conflicts.filter((c) => c.project === project).length,
      };
    });
}

export function formatCounts(c: ProjectCounts): string {
  return c.isNew
    ? `${c.project}: new project, ${c.added} added`
    : `${c.project}: ${c.added} added, ${c.keptLocal} kept local`;
}

export interface ApplyResult {
  vault: Vault;
  changed: boolean;
  peerId: string;
  peerName: string;
  counts: ProjectCounts[];
}

/**
 * Verify against the vault's pinned keys (no freshness — the bundle may have
 * been queued), decrypt, and merge receiver-wins. Pure; throws EnvelopeError.
 */
export function applyEnvelope(vault: Vault, env: SealedEnvelope): ApplyResult {
  const trust = trustFromVault(vault);
  if (!trust) throw new EnvelopeError("wrong-recipient", "this vault has no sync identity");
  const { peerId, peerName } = verifyEnvelope(env, trust);
  const projects = openEnvelope(env, vault.syncIdentity!);
  const { merged, report, changed } = mergeScopedProjects(vault, projects);
  return { vault: merged, changed, peerId, peerName, counts: countMerge(report, projects) };
}

export interface SyncInboxDeps {
  /** abra dir holding sync-inbox/. */
  base: string;
  /** Decrypted vault while unlocked; null when locked. */
  loadUnlockedVault: () => Promise<Vault | null>;
  saveVault: (vault: Vault) => Promise<void>;
  now?: () => number;
  log?: (line: string) => void;
}

export class SyncInbox {
  readonly queue: InboxQueue;
  readonly seen: ReplayCache;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly deps: SyncInboxDeps) {
    this.queue = new InboxQueue(deps.base);
    this.seen = new ReplayCache(deps.base);
  }

  private now(): number {
    return this.deps.now?.() ?? Date.now();
  }

  private log(line: string): void {
    this.deps.log?.(line);
  }

  /** Serialize inbox work so replay checks, queue writes and vault saves never interleave. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  private rejected(reason: InboxRejectReason, meta: { remote?: string }, bundleId?: string): InboxOutcome {
    this.log(`rejected reason=${reason}${meta.remote ? ` remote=${meta.remote}` : ""}`);
    return rejectOutcome(reason, bundleId);
  }

  async receive(raw: unknown, meta: { remote?: string } = {}): Promise<InboxOutcome> {
    let env: SealedEnvelope;
    try {
      env = parseEnvelope(raw);
    } catch {
      return this.rejected("malformed", meta);
    }
    return this.exclusive(() => this.receiveParsed(env, meta));
  }

  private async receiveParsed(env: SealedEnvelope, meta: { remote?: string }): Promise<InboxOutcome> {
    const now = this.now();
    let vault: Vault | null;
    try {
      vault = await this.deps.loadUnlockedVault();
    } catch {
      vault = null;
    }
    const trust = vault ? trustFromVault(vault) : trustFromAnchors(readAnchors(this.deps.base));
    if (!trust) return this.rejected("not-configured", meta);

    let peerId: string;
    let peerName: string;
    try {
      ({ peerId, peerName } = verifyEnvelope(env, trust, {
        now,
        checkFreshness: true,
        isReplay: (id) => this.seen.has(id) || this.queue.has(id),
      }));
    } catch (err) {
      return this.rejected(err instanceof EnvelopeError ? err.reason : "internal", meta);
    }

    if (vault && decideAccept(vault.syncAccept, peerId, env.projects).action === "auto") {
      try {
        const applied = applyEnvelope(vault, env);
        if (applied.changed) await this.deps.saveVault(applied.vault);
        this.seen.add(env.bundleId, env.createdAt, now);
        this.log(`applied bundle=${env.bundleId} from=${peerName} projects=${env.projects.length}`);
        return {
          response: { status: "applied" },
          httpStatus: 200,
          bundleId: env.bundleId,
          peerName,
          counts: applied.counts,
        };
      } catch (err) {
        if (err instanceof EnvelopeError) return this.rejected(err.reason, meta, env.bundleId);
        this.log(`apply failed bundle=${env.bundleId} — queueing instead`);
      }
    }

    try {
      this.queue.write({
        v: 1,
        receivedAt: now,
        ...(meta.remote ? { remote: meta.remote } : {}),
        verifiedWith: vault ? "vault" : "mirror",
        envelope: env,
      });
      this.seen.add(env.bundleId, env.createdAt, now);
    } catch (err) {
      return this.rejected(err instanceof InboxFullError ? "inbox-full" : "internal", meta, env.bundleId);
    }
    this.log(`queued bundle=${env.bundleId} from=${peerName}${vault ? "" : " (locked)"}`);
    return { response: { status: "queued" }, httpStatus: 202, bundleId: env.bundleId, peerName };
  }

  /**
   * Apply queued bundles that match an auto rule (called after unlock).
   * Anything that no longer verifies or isn't auto stays queued for the user.
   */
  async processQueue(): Promise<{ applied: number; remaining: number }> {
    return this.exclusive(async () => {
      let vault = await this.deps.loadUnlockedVault();
      if (!vault) return { applied: 0, remaining: this.queue.ids().length };
      let changed = false;
      const done: string[] = [];
      for (const id of this.queue.ids()) {
        try {
          const { envelope } = this.queue.read(id);
          const trust = trustFromVault(vault);
          if (!trust) break;
          const { peerId } = verifyEnvelope(envelope, trust);
          if (decideAccept(vault.syncAccept, peerId, envelope.projects).action !== "auto") continue;
          const r = applyEnvelope(vault, envelope);
          vault = r.vault;
          changed ||= r.changed;
          done.push(id);
        } catch {
          /* leave it for `abra sync inbox` */
        }
      }
      if (changed) await this.deps.saveVault(vault);
      for (const id of done) this.queue.remove(id);
      if (done.length > 0) this.log(`applied ${done.length} queued bundle(s) on unlock`);
      return { applied: done.length, remaining: this.queue.ids().length };
    });
  }
}

// ───────────────────────────── HTTP ─────────────────────────────

/** Fixed-window per-key limiter with a bounded key table. */
export class RateLimiter {
  private hits = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly maxKeys = 4096,
  ) {}

  allow(key: string, now: number): boolean {
    let h = this.hits.get(key);
    if (!h || now - h.start >= this.windowMs) {
      this.hits.delete(key);
      h = { start: now, count: 0 };
      this.hits.set(key, h);
      this.prune(now);
    }
    h.count += 1;
    return h.count <= this.max;
  }

  private prune(now: number): void {
    if (this.hits.size <= this.maxKeys) return;
    for (const [k, v] of this.hits) if (now - v.start >= this.windowMs) this.hits.delete(k);
    for (const k of this.hits.keys()) {
      if (this.hits.size <= this.maxKeys) break;
      this.hits.delete(k);
    }
  }
}

export function normalizeRemote(addr: string | undefined): string {
  return (addr ?? "unknown").replace(/^::ffff:/, "");
}

export interface InboxHttpOptions {
  maxBodyBytes?: number;
  rateLimit?: { max: number; windowMs: number };
  now?: () => number;
  log?: (line: string) => void;
}

export type ReceiveFn = (raw: unknown, meta: { remote?: string }) => Promise<InboxOutcome>;

/** POST /v1/sync/inbox — JSON only, size-capped, rate-limited per remote IP. */
export function createInboxRequestHandler(
  receive: ReceiveFn,
  opts: InboxHttpOptions = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  const maxBody = opts.maxBodyBytes ?? INBOX_MAX_BODY_BYTES;
  const rl = opts.rateLimit ?? INBOX_RATE_LIMIT;
  const limiter = new RateLimiter(rl.max, rl.windowMs);
  const now = opts.now ?? Date.now;

  return (req, res) => {
    const remote = normalizeRemote(req.socket.remoteAddress);
    let answered = false;
    const send = (code: number, body: InboxResponse) => {
      if (answered) return;
      answered = true;
      const data = JSON.stringify(body);
      res.writeHead(code, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
        "Cache-Control": "no-store",
        Connection: "close",
      });
      res.end(data);
    };
    // Read and discard the rest of a rejected body (bounded) so the socket closes
    // gracefully — closing with unread bytes sends RST, and Windows clients then
    // drop the response.
    let drained = 0;
    const discard = (chunk: Buffer) => {
      drained += chunk.length;
      if (drained > INBOX_DRAIN_CAP_BYTES) req.destroy();
    };
    const early = (reason: InboxRejectReason) => {
      if (reason !== "rate-limited") opts.log?.(`rejected reason=${reason} remote=${remote}`);
      const o = rejectOutcome(reason);
      send(o.httpStatus, o.response);
      req.on("data", discard);
    };

    if (!limiter.allow(remote, now())) return early("rate-limited");
    if ((req.url ?? "").split("?")[0] !== INBOX_PATH) return early("not-found");
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST");
      return early("method-not-allowed");
    }
    const ctype = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (ctype !== "application/json") return early("unsupported-media-type");
    const declared = Number(req.headers["content-length"] ?? NaN);
    if (Number.isFinite(declared) && declared > maxBody) return early("too-large");

    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    const collect = (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBody) {
        over = true;
        chunks.length = 0;
        req.off("data", collect);
        early("too-large");
        return;
      }
      chunks.push(chunk);
    };
    req.on("data", collect);
    req.on("error", () => req.destroy());
    req.on("end", () => {
      if (over) return;
      let raw: unknown;
      try {
        raw = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        opts.log?.(`rejected reason=malformed remote=${remote}`);
        const o = rejectOutcome("malformed");
        send(o.httpStatus, o.response);
        return;
      }
      receive(raw, { remote }).then(
        (o) => send(o.httpStatus, o.response),
        () => {
          const o = rejectOutcome("internal");
          send(o.httpStatus, o.response);
        },
      );
    });
  };
}

export interface InboxListener {
  bind: string;
  port: number;
  close(): Promise<void>;
}

/**
 * HTTPS listener for the inbox. TLS here is transport privacy only; every
 * envelope is authenticated by its Ed25519 signature against pinned keys.
 */
export async function startInboxListener(opts: {
  bind: string;
  port: number;
  tls: { key: string; cert: string };
  handler: (req: IncomingMessage, res: ServerResponse) => void;
}): Promise<InboxListener> {
  const server = https.createServer({ key: opts.tls.key, cert: opts.tls.cert, minVersion: "TLSv1.2" }, opts.handler);
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 64;
  server.maxConnections = 64;
  server.on("tlsClientError", () => {
    /* scanners / wrong-protocol clients */
  });
  server.on("clientError", (_err, socket) => socket.destroy());

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, opts.bind, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  server.on("error", () => {
    /* keep the agent alive on late socket errors */
  });
  const addr = server.address();
  const port = addr && typeof addr === "object" ? addr.port : opts.port;
  return {
    bind: opts.bind,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
