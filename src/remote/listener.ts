import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createEphemeralTls, fingerprintOfPem, type EphemeralTls } from "../core/tls-ephemeral.js";
import { RateLimiter, normalizeRemote } from "../sync/inbox.js";
import { detectTailscaleIPv4 } from "../sync/tailscale.js";
import { appendAuditLog } from "./audit.js";
import { loadDeviceKey, type DeviceKey } from "./device-key.js";
import type { EnrollOffer } from "./enroll-seal.js";
import { isRemoteUnlockEnabled } from "./feature.js";
import { getHubPin } from "./hub-pin.js";
import { NonceCache } from "./nonce-cache.js";
import {
  clampUnlockPolicy,
  localUnlockCaps,
  type AppliedUnlockPolicy,
  type UnlockPolicyCaps,
} from "./policy.js";
import { ensureRemoteDir, remoteDir, writePrivateFile, assertPrivatePath } from "./private-fs.js";
import { readUnlockBlob, unwrapMasterKey } from "./unlock-blob.js";
import {
  ENROLL_PATH,
  LOCK_PATH,
  REMOTE_UNLOCK_PORT,
  STATUS_PATH,
  UNLOCK_MAX_BODY_BYTES,
  UNLOCK_PATH,
  UnlockWireError,
  issueUnlockChallenge,
  openWrapKeyFromResponse,
  parseLockRequest,
  parseUnlockWireMessage,
  verifyLockRequest,
  verifyUnlockResponse,
  type UnlockChallenge,
  type UnlockResponse,
} from "./wire.js";

/**
 * Tailnet-only remote-unlock HTTPS listener (port 7335).
 * Off unless ABRA_REMOTE_UNLOCK=1 and enrolled (device key + hub pin + blob).
 * Bind logic mirrors the sync inbox: Tailscale IPv4, or an explicit bind.
 */

export const UNLOCK_RATE_LIMIT = { max: 10, windowMs: 60_000 };
const DRAIN_CAP_BYTES = 64 * 1024;

export type UnlockRejectReason =
  | "disabled"
  | "not-enrolled"
  | "not-unlocked"
  | "malformed"
  | "bad-signature"
  | "expired"
  | "replay"
  | "wrong-hub"
  | "wrong-device"
  | "decrypt-failed"
  | "stale-challenge"
  | "too-large"
  | "unsupported-media-type"
  | "rate-limited"
  | "not-found"
  | "method-not-allowed"
  | "already-unlocked"
  | "already-locked"
  | "unlock-failed"
  | "lock-failed"
  | "enroll-failed"
  | "internal";

const PUBLIC_REJECT: Record<UnlockRejectReason, [number, string]> = {
  disabled: [503, "disabled"],
  "not-enrolled": [503, "not-enrolled"],
  "not-unlocked": [503, "not-unlocked"],
  malformed: [400, "bad-request"],
  "bad-signature": [403, "unauthorized"],
  expired: [403, "expired"],
  replay: [409, "replay"],
  "wrong-hub": [403, "unauthorized"],
  "wrong-device": [403, "unauthorized"],
  "decrypt-failed": [403, "unauthorized"],
  "stale-challenge": [403, "stale"],
  "too-large": [413, "too-large"],
  "unsupported-media-type": [415, "unsupported-media-type"],
  "rate-limited": [429, "rate-limited"],
  "not-found": [404, "not-found"],
  "method-not-allowed": [405, "method-not-allowed"],
  "already-unlocked": [409, "already-unlocked"],
  "already-locked": [409, "already-locked"],
  "unlock-failed": [500, "unlock-failed"],
  "lock-failed": [500, "lock-failed"],
  "enroll-failed": [500, "enroll-failed"],
  internal: [500, "internal"],
};

export interface UnlockHttpResponse {
  status: "challenge" | "unlocked" | "locked" | "offer" | "ok" | "rejected";
  reason?: string;
  challenge?: UnlockChallenge;
  offer?: EnrollOffer;
  /** Public TLS cert PEM for hub TOFU / unlockWrap.listenerCert. */
  listenerCert?: string;
  enrolled?: boolean;
  locked?: boolean;
  deviceId?: string;
  /** Applied idle/max-age after local clamp (unlocked only). */
  policy?: AppliedUnlockPolicy;
}

export interface UnlockOutcome {
  response: UnlockHttpResponse;
  httpStatus: number;
  reason?: UnlockRejectReason;
  /** Device id for logs (never secrets). */
  peer?: string;
  op?: "challenge" | "response";
}

function rejectOutcome(reason: UnlockRejectReason, peer?: string, op?: "challenge" | "response"): UnlockOutcome {
  const [httpStatus, publicReason] = PUBLIC_REJECT[reason];
  return {
    response: { status: "rejected", reason: publicReason },
    httpStatus,
    reason,
    peer,
    op,
  };
}

/** True when feature flag is on and enroll artifacts exist (works while vault locked). */
export function isRemoteUnlockEnrolled(base: string): boolean {
  if (!isRemoteUnlockEnabled()) return false;
  try {
    loadDeviceKey(base);
    if (!getHubPin(base)) return false;
    if (!readUnlockBlob(base)) return false;
    return true;
  } catch {
    return false;
  }
}

export function loadOrCreateRemoteUnlockTls(
  base: string,
  create: (commonName: string) => EphemeralTls = (cn) => createEphemeralTls(cn, { days: 3650 }),
): EphemeralTls {
  ensureRemoteDir(base);
  const dir = remoteDir(base);
  const keyFile = path.join(dir, "tls-key.pem");
  const certFile = path.join(dir, "tls-cert.pem");
  try {
    assertPrivatePath(keyFile, { expectDir: false });
    assertPrivatePath(certFile, { expectDir: false });
    const key = fs.readFileSync(keyFile, "utf8");
    const cert = fs.readFileSync(certFile, "utf8");
    return { key, cert, fingerprint: fingerprintOfPem(cert) };
  } catch {
    const tls = create("abra-remote-unlock");
    writePrivateFile(keyFile, tls.key);
    writePrivateFile(certFile, tls.cert);
    return tls;
  }
}

export interface UnlockSessionDeps {
  base: string;
  /**
   * Apply master key in-process (agent unlockWithKey). Must zero the buffer.
   * `policy` is already clamped to local caps (idle/max-age seconds).
   */
  unlockWithKey: (
    masterKey: Buffer,
    policy: AppliedUnlockPolicy,
  ) => void | Promise<void>;
  /** Lock the in-process vault (remote lock). */
  lockVault?: () => void | Promise<void>;
  /** Optional: refuse unlock if already unlocked; used by status/lock. */
  isLocked?: () => boolean;
  /** Validate master key decrypts vault.enc before accepting (optional). */
  verifyMasterKey?: (masterKey: Buffer) => boolean;
  /**
   * Build an enroll offer while the vault is unlocked (hubId = how this
   * receiver names the hub / source peer).
   */
  prepareEnrollOffer?: (hubNameOrId: string) => EnrollOffer | Promise<EnrollOffer>;
  /** Listener TLS cert PEM returned with enroll offers (public). */
  listenerCert?: () => string | null;
  loadDeviceKey?: (base: string) => DeviceKey;
  now?: () => number;
  log?: (line: string) => void;
  /** Override audit append (tests). */
  audit?: typeof appendAuditLog;
  nonceCache?: NonceCache;
  /** Called when enroll artifacts disappear mid-flight (disable). */
  onNotEnrolled?: () => void;
  /** Override local idle/max-age caps (tests). Default: agent env caps. */
  localCaps?: () => UnlockPolicyCaps;
}

/**
 * In-process challenge/response (+ lock / status / enroll) handler.
 * Logs and audits op/peer/result only — never secrets.
 */
export class UnlockSession {
  readonly nonces: NonceCache;

  constructor(private readonly deps: UnlockSessionDeps) {
    this.nonces = deps.nonceCache ?? new NonceCache();
  }

  private log(op: string, peer: string | undefined, result: string): void {
    const p = peer ? ` peer=${peer}` : "";
    this.deps.log?.(`op=${op}${p} result=${result}`);
    (this.deps.audit ?? appendAuditLog)(
      { op, peer, result },
      { base: this.deps.base, now: this.deps.now },
    );
  }

  /** Issue a fresh challenge (receiver side). */
  issueChallenge(): UnlockOutcome {
    if (!isRemoteUnlockEnabled()) {
      this.log("challenge", undefined, "disabled");
      return rejectOutcome("disabled", undefined, "challenge");
    }
    if (!isRemoteUnlockEnrolled(this.deps.base)) {
      this.log("challenge", undefined, "not-enrolled");
      return rejectOutcome("not-enrolled", undefined, "challenge");
    }
    const now = (this.deps.now ?? Date.now)();
    const deviceKey = (this.deps.loadDeviceKey ?? loadDeviceKey)(this.deps.base);
    const issued = issueUnlockChallenge(deviceKey, { now });
    const ok = this.nonces.addPending(
      issued.message.nonce,
      {
        ephPrivateRaw: issued.ephPrivateRaw,
        ephPublic: issued.message.epk,
        deviceId: deviceKey.id,
        createdAt: now,
      },
      now,
    );
    if (!ok) {
      issued.ephPrivateRaw.fill(0);
      this.log("challenge", deviceKey.id, "internal");
      return rejectOutcome("internal", deviceKey.id, "challenge");
    }
    this.log("challenge", deviceKey.id, "ok");
    return {
      response: { status: "challenge", challenge: issued.message },
      httpStatus: 200,
      peer: deviceKey.id,
      op: "challenge",
    };
  }

  /** Process a hub response: verify, unwrap, unlock. */
  async acceptResponse(raw: unknown): Promise<UnlockOutcome> {
    if (!isRemoteUnlockEnabled()) {
      this.log("response", undefined, "disabled");
      return rejectOutcome("disabled", undefined, "response");
    }
    if (!isRemoteUnlockEnrolled(this.deps.base)) {
      this.log("response", undefined, "not-enrolled");
      return rejectOutcome("not-enrolled", undefined, "response");
    }

    let response: UnlockResponse;
    try {
      const msg = parseUnlockWireMessage(raw);
      if (msg.op !== "response") {
        this.log("response", undefined, "malformed");
        return rejectOutcome("malformed", undefined, "response");
      }
      response = msg;
    } catch (err) {
      const reason =
        err instanceof UnlockWireError ? (err.reason as UnlockRejectReason) : "malformed";
      this.log("response", undefined, reason);
      return rejectOutcome(reason === "malformed" ? "malformed" : reason, undefined, "response");
    }

    const peer = response.peerId;
    const now = (this.deps.now ?? Date.now)();

    if (this.deps.isLocked && !this.deps.isLocked()) {
      this.log("response", peer, "already-unlocked");
      return rejectOutcome("already-unlocked", peer, "response");
    }

    if (this.nonces.isUsed(response.nonce, now)) {
      this.log("response", peer, "replay");
      return rejectOutcome("replay", peer, "response");
    }

    const pending = this.nonces.takePending(response.nonce, now);
    if (!pending) {
      this.log("response", peer, "stale-challenge");
      return rejectOutcome("stale-challenge", peer, "response");
    }

    const hubPin = getHubPin(this.deps.base);
    if (!hubPin) {
      pending.ephPrivateRaw.fill(0);
      this.log("response", peer, "not-enrolled");
      return rejectOutcome("not-enrolled", peer, "response");
    }

    let wrapKey: Buffer | null = null;
    let masterKey: Buffer | null = null;
    try {
      verifyUnlockResponse(response, hubPin, {
        now,
        expectedPeerId: pending.deviceId,
      });
      wrapKey = openWrapKeyFromResponse(response, pending.ephPublic, pending.ephPrivateRaw);
      const blob = readUnlockBlob(this.deps.base);
      if (!blob) throw new UnlockWireError("decrypt-failed", "unlock blob missing");
      masterKey = unwrapMasterKey(blob, wrapKey);
      if (this.deps.verifyMasterKey && !this.deps.verifyMasterKey(masterKey)) {
        masterKey.fill(0);
        masterKey = null;
        this.log("response", peer, "unlock-failed");
        return rejectOutcome("unlock-failed", peer, "response");
      }
      let applied: AppliedUnlockPolicy;
      try {
        applied = clampUnlockPolicy(
          response.policy,
          (this.deps.localCaps ?? localUnlockCaps)(),
        );
      } catch {
        this.log("response", peer, "malformed");
        return rejectOutcome("malformed", peer, "response");
      }
      await this.deps.unlockWithKey(masterKey, applied);
      this.nonces.markUsed(response.nonce, now);
      this.log("response", peer, "unlocked");
      return {
        response: {
          status: "unlocked",
          policy: applied,
        },
        httpStatus: 200,
        peer,
        op: "response",
      };
    } catch (err) {
      let reason: UnlockRejectReason = "internal";
      if (err instanceof UnlockWireError) {
        reason = err.reason as UnlockRejectReason;
      }
      this.log("response", peer, reason);
      return rejectOutcome(reason, peer, "response");
    } finally {
      pending.ephPrivateRaw.fill(0);
      wrapKey?.fill(0);
      masterKey?.fill(0);
    }
  }

  /** Dispatch unlock path: empty/{op:challenge} → challenge; response → accept. */
  async handle(raw: unknown): Promise<UnlockOutcome> {
    if (raw === null || raw === undefined) return this.issueChallenge();
    if (typeof raw === "object" && !Array.isArray(raw)) {
      const o = raw as Record<string, unknown>;
      if (Object.keys(o).length === 0 || o.op === "challenge") {
        return this.issueChallenge();
      }
      if (o.op === "response" || ("ct" in o && "sig" in o && "nonce" in o)) {
        return this.acceptResponse(raw);
      }
    }
    this.log("challenge", undefined, "malformed");
    return rejectOutcome("malformed");
  }

  /** Status probe — enrolled / locked only; no secrets. */
  status(): UnlockOutcome {
    if (!isRemoteUnlockEnabled()) {
      this.log("status", undefined, "disabled");
      return rejectOutcome("disabled", undefined, "challenge");
    }
    const enrolled = isRemoteUnlockEnrolled(this.deps.base);
    if (!enrolled) this.deps.onNotEnrolled?.();
    let deviceId: string | undefined;
    try {
      deviceId = (this.deps.loadDeviceKey ?? loadDeviceKey)(this.deps.base).id;
    } catch {
      deviceId = undefined;
    }
    const locked = this.deps.isLocked ? this.deps.isLocked() : true;
    this.log("status", deviceId, "ok");
    return {
      response: {
        status: "ok",
        enrolled,
        locked,
        ...(deviceId ? { deviceId } : {}),
      },
      httpStatus: 200,
      peer: deviceId,
      op: "challenge",
    };
  }

  /** Signed lock from hub — no Touch ID on either side. */
  async acceptLock(raw: unknown): Promise<UnlockOutcome> {
    if (!isRemoteUnlockEnabled()) {
      this.log("lock", undefined, "disabled");
      return rejectOutcome("disabled", undefined, "response");
    }
    if (!isRemoteUnlockEnrolled(this.deps.base)) {
      this.deps.onNotEnrolled?.();
      this.log("lock", undefined, "not-enrolled");
      return rejectOutcome("not-enrolled", undefined, "response");
    }

    let request;
    try {
      request = parseLockRequest(raw);
    } catch (err) {
      const reason =
        err instanceof UnlockWireError ? (err.reason as UnlockRejectReason) : "malformed";
      this.log("lock", undefined, reason);
      return rejectOutcome(reason === "malformed" ? "malformed" : reason, undefined, "response");
    }

    const peer = request.peerId;
    const now = (this.deps.now ?? Date.now)();
    if (this.deps.isLocked?.()) {
      this.log("lock", peer, "already-locked");
      return rejectOutcome("already-locked", peer, "response");
    }

    const deviceKey = (this.deps.loadDeviceKey ?? loadDeviceKey)(this.deps.base);
    const hubPin = getHubPin(this.deps.base);
    if (!hubPin) {
      this.log("lock", peer, "not-enrolled");
      return rejectOutcome("not-enrolled", peer, "response");
    }

    try {
      verifyLockRequest(request, hubPin, { now, expectedPeerId: deviceKey.id });
      if (!this.deps.lockVault) {
        this.log("lock", peer, "lock-failed");
        return rejectOutcome("lock-failed", peer, "response");
      }
      await this.deps.lockVault();
      this.log("lock", peer, "locked");
      return {
        response: { status: "locked" },
        httpStatus: 200,
        peer,
        op: "response",
      };
    } catch (err) {
      let reason: UnlockRejectReason = "internal";
      if (err instanceof UnlockWireError) reason = err.reason as UnlockRejectReason;
      this.log("lock", peer, reason);
      return rejectOutcome(reason, peer, "response");
    }
  }

  /**
   * Hub asks for a sealed enroll offer. Requires an unlocked vault (and the
   * feature flag). Works before the blob exists (first enroll).
   */
  async acceptEnrollRequest(raw: unknown): Promise<UnlockOutcome> {
    if (!isRemoteUnlockEnabled()) {
      this.log("enroll", undefined, "disabled");
      return rejectOutcome("disabled");
    }
    if (this.deps.isLocked?.()) {
      this.log("enroll", undefined, "not-unlocked");
      return rejectOutcome("not-unlocked");
    }
    if (!this.deps.prepareEnrollOffer) {
      this.log("enroll", undefined, "enroll-failed");
      return rejectOutcome("enroll-failed");
    }

    let hubNameOrId: string | undefined;
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      const o = raw as Record<string, unknown>;
      if (o.op !== undefined && o.op !== "offer" && o.op !== "enroll") {
        this.log("enroll", undefined, "malformed");
        return rejectOutcome("malformed");
      }
      if (typeof o.hub === "string") hubNameOrId = o.hub;
      else if (typeof o.hubNameOrId === "string") hubNameOrId = o.hubNameOrId;
    }
    if (!hubNameOrId) {
      this.log("enroll", undefined, "malformed");
      return rejectOutcome("malformed");
    }

    try {
      const offer = await this.deps.prepareEnrollOffer(hubNameOrId);
      const cert = this.deps.listenerCert?.() ?? null;
      let deviceId: string | undefined;
      try {
        deviceId = (this.deps.loadDeviceKey ?? loadDeviceKey)(this.deps.base).id;
      } catch {
        deviceId = undefined;
      }
      this.log("enroll", deviceId ?? hubNameOrId, "offer");
      return {
        response: {
          status: "offer",
          offer,
          ...(cert ? { listenerCert: cert } : {}),
        },
        httpStatus: 200,
        peer: deviceId,
        op: "challenge",
      };
    } catch {
      this.log("enroll", hubNameOrId, "enroll-failed");
      return rejectOutcome("enroll-failed");
    }
  }
}

export type UnlockReceiveFn = (raw: unknown, meta: { remote?: string }) => Promise<UnlockOutcome>;

export type RemotePath =
  | typeof UNLOCK_PATH
  | typeof LOCK_PATH
  | typeof STATUS_PATH
  | typeof ENROLL_PATH;

export type RemoteReceiveFn = (
  path: RemotePath,
  raw: unknown,
  meta: { remote?: string },
) => Promise<UnlockOutcome>;

export interface UnlockHttpOptions {
  maxBodyBytes?: number;
  rateLimit?: { max: number; windowMs: number };
  now?: () => number;
  log?: (line: string) => void;
}

const REMOTE_PATHS = new Set<string>([UNLOCK_PATH, LOCK_PATH, STATUS_PATH, ENROLL_PATH]);

/** Route POST /v1/remote/{unlock,lock,status,enroll} — JSON, size-capped, rate-limited. */
export function createRemoteRequestHandler(
  receive: RemoteReceiveFn,
  opts: UnlockHttpOptions = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  const maxBody = opts.maxBodyBytes ?? UNLOCK_MAX_BODY_BYTES;
  const rl = opts.rateLimit ?? UNLOCK_RATE_LIMIT;
  const limiter = new RateLimiter(rl.max, rl.windowMs);
  const now = opts.now ?? Date.now;

  return (req, res) => {
    const remote = normalizeRemote(req.socket.remoteAddress);
    let answered = false;
    const send = (code: number, body: UnlockHttpResponse) => {
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
    let drained = 0;
    const discard = (chunk: Buffer) => {
      drained += chunk.length;
      if (drained > DRAIN_CAP_BYTES) req.destroy();
    };
    const early = (reason: UnlockRejectReason) => {
      if (reason !== "rate-limited") opts.log?.(`op=http peer=${remote} result=${reason}`);
      const o = rejectOutcome(reason);
      send(o.httpStatus, o.response);
      req.on("data", discard);
    };

    if (!limiter.allow(remote, now())) return early("rate-limited");
    const urlPath = (req.url ?? "").split("?")[0] ?? "";
    if (!REMOTE_PATHS.has(urlPath)) return early("not-found");
    const path = urlPath as RemotePath;
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
        const text = Buffer.concat(chunks).toString("utf8").trim();
        raw = text.length === 0 ? {} : JSON.parse(text);
      } catch {
        opts.log?.(`op=http peer=${remote} result=malformed`);
        const o = rejectOutcome("malformed");
        send(o.httpStatus, o.response);
        return;
      }
      receive(path, raw, { remote }).then(
        (o) => send(o.httpStatus, o.response),
        () => {
          const o = rejectOutcome("internal");
          send(o.httpStatus, o.response);
        },
      );
    });
  };
}

/** POST /v1/remote/unlock only — thin wrapper for older tests. */
export function createUnlockRequestHandler(
  receive: UnlockReceiveFn,
  opts: UnlockHttpOptions = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  return createRemoteRequestHandler((path, raw, meta) => {
    if (path !== UNLOCK_PATH) {
      return Promise.resolve(rejectOutcome("not-found"));
    }
    return receive(raw, meta);
  }, opts);
}

/** Dispatch a RemotePath against an UnlockSession. */
export function dispatchRemoteSession(
  session: UnlockSession,
  path: RemotePath,
  raw: unknown,
): Promise<UnlockOutcome> {
  switch (path) {
    case UNLOCK_PATH:
      return session.handle(raw);
    case LOCK_PATH:
      return session.acceptLock(raw);
    case STATUS_PATH:
      return Promise.resolve(session.status());
    case ENROLL_PATH:
      return session.acceptEnrollRequest(raw);
    default:
      return Promise.resolve(rejectOutcome("not-found"));
  }
}

export interface UnlockListener {
  bind: string;
  port: number;
  close(): Promise<void>;
}

/** HTTPS listener — TLS is transport privacy; authenticity is Ed25519 + seal. */
export async function startUnlockListener(opts: {
  bind: string;
  port: number;
  tls: { key: string; cert: string };
  handler: (req: IncomingMessage, res: ServerResponse) => void;
}): Promise<UnlockListener> {
  const server = https.createServer(
    { key: opts.tls.key, cert: opts.tls.cert, minVersion: "TLSv1.2" },
    opts.handler,
  );
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 64;
  server.maxConnections = 32;
  server.on("tlsClientError", () => {
    /* scanners */
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
    /* keep agent alive */
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

export { REMOTE_UNLOCK_PORT, detectTailscaleIPv4 };
