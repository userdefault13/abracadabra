import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createEphemeralTls, fingerprintOfPem, type EphemeralTls } from "../core/tls-ephemeral.js";
import { RateLimiter, normalizeRemote } from "../sync/inbox.js";
import { detectTailscaleIPv4 } from "../sync/tailscale.js";
import { loadDeviceKey, type DeviceKey } from "./device-key.js";
import { isRemoteUnlockEnabled } from "./feature.js";
import { getHubPin } from "./hub-pin.js";
import { NonceCache } from "./nonce-cache.js";
import { ensureRemoteDir, remoteDir, writePrivateFile, assertPrivatePath } from "./private-fs.js";
import { readUnlockBlob, unwrapMasterKey } from "./unlock-blob.js";
import {
  REMOTE_UNLOCK_PORT,
  UNLOCK_MAX_BODY_BYTES,
  UNLOCK_PATH,
  UnlockWireError,
  issueUnlockChallenge,
  openWrapKeyFromResponse,
  parseUnlockWireMessage,
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
  | "unlock-failed"
  | "internal";

const PUBLIC_REJECT: Record<UnlockRejectReason, [number, string]> = {
  disabled: [503, "disabled"],
  "not-enrolled": [503, "not-enrolled"],
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
  "unlock-failed": [500, "unlock-failed"],
  internal: [500, "internal"],
};

export interface UnlockHttpResponse {
  status: "challenge" | "unlocked" | "rejected";
  reason?: string;
  challenge?: UnlockChallenge;
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
  /** Apply master key in-process (agent unlockWithKey). Must zero the buffer. */
  unlockWithKey: (masterKey: Buffer) => void | Promise<void>;
  /** Optional: refuse if already unlocked. */
  isLocked?: () => boolean;
  /** Validate master key decrypts vault.enc before accepting (optional). */
  verifyMasterKey?: (masterKey: Buffer) => boolean;
  loadDeviceKey?: (base: string) => DeviceKey;
  now?: () => number;
  log?: (line: string) => void;
  nonceCache?: NonceCache;
}

/**
 * In-process challenge/response handler (no HTTP). Used by the HTTPS handler
 * and by tests. Logs op/peer/result only.
 */
export class UnlockSession {
  readonly nonces: NonceCache;

  constructor(private readonly deps: UnlockSessionDeps) {
    this.nonces = deps.nonceCache ?? new NonceCache();
  }

  private log(op: string, peer: string | undefined, result: string): void {
    const p = peer ? ` peer=${peer}` : "";
    this.deps.log?.(`op=${op}${p} result=${result}`);
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
      await this.deps.unlockWithKey(masterKey);
      this.nonces.markUsed(response.nonce, now);
      this.log("response", peer, "unlocked");
      return {
        response: { status: "unlocked" },
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

  /** Dispatch: empty/{op:challenge} → challenge; response object → accept. */
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
}

export type UnlockReceiveFn = (raw: unknown, meta: { remote?: string }) => Promise<UnlockOutcome>;

export interface UnlockHttpOptions {
  maxBodyBytes?: number;
  rateLimit?: { max: number; windowMs: number };
  now?: () => number;
  log?: (line: string) => void;
}

/** POST /v1/remote/unlock — JSON only, size-capped, rate-limited per remote IP. */
export function createUnlockRequestHandler(
  receive: UnlockReceiveFn,
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
      // Never echo secrets — challenge pubs/nonces are not vault secrets but keep body minimal.
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
    if ((req.url ?? "").split("?")[0] !== UNLOCK_PATH) return early("not-found");
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
