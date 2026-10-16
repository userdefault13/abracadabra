import crypto, { type KeyObject } from "node:crypto";
import type { Project, SyncIdentity, VarEntry } from "../core/vault.js";
import type { GrantCaller } from "../agent/grants.js";
import {
  decodeRawKey,
  ed25519PrivateKey,
  ed25519PublicKey,
  isUuid,
  lengthPrefixed,
  rawPublicKey,
  x25519PublicKey,
} from "../sync/identity.js";
import type { DeviceKey } from "./device-key.js";
import type { HubPin } from "./hub-pin.js";

/**
 * Scoped bot lease (Phase 2 / PR 6): one project's secrets re-encrypted to the
 * receiver device X25519 key, signed by the hub Ed25519 key, bound to a
 * GrantCaller (exe+dev+ino). Survives vault lock; served only to that binary.
 *
 * Domain-separated from sync envelopes / enroll / unlock seals.
 */

export const LEASE_DOMAIN = "abra-remote-lease-v1";
const SIG_DOMAIN = `${LEASE_DOMAIN}/sig`;
export const LEASE_VERSION = 1;
export const LEASE_PATH = "/v1/remote/lease";
export const LEASE_REVOKE_PATH = "/v1/remote/lease-revoke";
/** Default / hard max TTL unless ABRA_LEASE_MAX_TTL_SECONDS raises or lowers the cap. */
export const LEASE_DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
export const LEASE_MAX_TTL_SECONDS = LEASE_DEFAULT_TTL_SECONDS;
/** Hub grant/renew hard ceiling — refuse above 7d (no silent clamp). */
export const LEASE_HUB_HARD_MAX_TTL_SECONDS = LEASE_DEFAULT_TTL_SECONDS;
export const LEASE_MAX_BODY_BYTES = 1 * 1024 * 1024;
/** Signed revoke message expiry (same window as unlock/lock responses). */
export const LEASE_REVOKE_TTL_MS = 30_000;
const REVOKE_NONCE_BYTES = 32;
const SIG_REVOKE_DOMAIN = `${LEASE_DOMAIN}/revoke-sig`;

const GCM_TAG_BYTES = 16;
const NONCE_BYTES = 12;

export type LeaseRejectReason =
  | "malformed"
  | "bad-signature"
  | "expired"
  | "wrong-hub"
  | "wrong-device"
  | "wrong-project"
  | "wrong-binding"
  | "ttl-exceeded"
  | "decrypt-failed"
  | "disabled"
  | "not-enrolled";

export class LeaseError extends Error {
  constructor(
    readonly reason: LeaseRejectReason,
    message: string,
  ) {
    super(message);
    this.name = "LeaseError";
  }
}

export interface LeaseBinding {
  exe: string;
  dev: number;
  ino: number;
}

export interface SealedLease {
  v: typeof LEASE_VERSION;
  op: "lease";
  leaseId: string;
  /** Hub sync / pin id (must match hub-pin.deviceId). */
  from: string;
  /** Receiver device-key id. */
  peerId: string;
  project: string;
  binding: LeaseBinding;
  issuedAt: number;
  expiresAt: number;
  epk: string;
  nonce: string;
  ct: string;
  sig: string;
}

interface LeasePayload {
  v: typeof LEASE_VERSION;
  project: string;
  vars: Record<string, VarEntry>;
  createdAt: number;
}

function strictB64(value: unknown, bytes: number | "any"): Buffer | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const buf = Buffer.from(value, "base64");
  if (buf.toString("base64") !== value) return null;
  if (bytes !== "any" && buf.length !== bytes) return null;
  return buf;
}

function isLeaseBinding(raw: unknown): raw is LeaseBinding {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const b = raw as Record<string, unknown>;
  return (
    typeof b.exe === "string" &&
    b.exe.length > 0 &&
    typeof b.dev === "number" &&
    Number.isFinite(b.dev) &&
    typeof b.ino === "number" &&
    Number.isFinite(b.ino)
  );
}

export function bindingEquals(a: LeaseBinding, b: LeaseBinding): boolean {
  return a.exe === b.exe && a.dev === b.dev && a.ino === b.ino;
}

export function bindingKey(b: LeaseBinding): string {
  return `${b.exe}\0${b.dev}\0${b.ino}`;
}

function headerBytes(h: Omit<SealedLease, "ct" | "sig">): Buffer {
  return lengthPrefixed([
    Buffer.from(LEASE_DOMAIN, "utf8"),
    Buffer.from(String(h.v), "utf8"),
    Buffer.from(h.op, "utf8"),
    Buffer.from(h.leaseId, "utf8"),
    Buffer.from(h.from, "utf8"),
    Buffer.from(h.peerId, "utf8"),
    Buffer.from(h.project, "utf8"),
    Buffer.from(h.binding.exe, "utf8"),
    Buffer.from(String(h.binding.dev), "utf8"),
    Buffer.from(String(h.binding.ino), "utf8"),
    Buffer.from(String(h.issuedAt), "utf8"),
    Buffer.from(String(h.expiresAt), "utf8"),
    decodeRawKey(h.epk),
    Buffer.from(h.nonce, "base64"),
  ]);
}

function sigMessage(h: Omit<SealedLease, "ct" | "sig">, ct: Buffer): Buffer {
  return lengthPrefixed([Buffer.from(SIG_DOMAIN, "utf8"), headerBytes(h), ct]);
}

function deriveKey(shared: Buffer, h: Omit<SealedLease, "ct" | "sig">, recipientX25519: string): Buffer {
  if (shared.every((b) => b === 0)) throw new Error("degenerate X25519 shared secret");
  const info = lengthPrefixed([
    Buffer.from(LEASE_DOMAIN, "utf8"),
    Buffer.from(h.from, "utf8"),
    Buffer.from(h.peerId, "utf8"),
    decodeRawKey(h.epk),
    decodeRawKey(recipientX25519),
  ]);
  return Buffer.from(
    crypto.hkdfSync("sha256", shared, Buffer.from(LEASE_DOMAIN, "utf8"), info, 32),
  );
}

function x25519PrivFromDevice(device: DeviceKey): KeyObject {
  decodeRawKey(device.x25519.privateKey);
  const b64ToB64url = (s: string) => Buffer.from(s, "base64").toString("base64url");
  return crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: b64ToB64url(device.x25519.publicKey),
      d: b64ToB64url(device.x25519.privateKey),
    },
    format: "jwk",
  });
}

function cleanEntry(raw: unknown): VarEntry {
  const e = raw as Record<string, unknown>;
  if (
    !e ||
    typeof e !== "object" ||
    typeof e.value !== "string" ||
    typeof e.secret !== "boolean" ||
    typeof e.updatedAt !== "number" ||
    !Number.isFinite(e.updatedAt)
  ) {
    throw new LeaseError("malformed", "malformed lease var entry");
  }
  return { value: e.value, secret: e.secret, updatedAt: e.updatedAt };
}

function sanitizeProjectVars(raw: unknown): Record<string, VarEntry> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new LeaseError("malformed", "lease vars must be an object");
  }
  const out: Record<string, VarEntry> = {};
  for (const [key, entry] of Object.entries(raw as Record<string, unknown>)) {
    if (!key || key === "__proto__") throw new LeaseError("malformed", "invalid var name");
    out[key] = cleanEntry(entry);
  }
  return out;
}

/** Local max lease TTL (seconds). Default 7d; override with ABRA_LEASE_MAX_TTL_SECONDS. */
export function localLeaseMaxTtlSeconds(): number {
  const raw = process.env.ABRA_LEASE_MAX_TTL_SECONDS?.trim();
  if (raw) {
    const n = Number(raw);
    if (Number.isSafeInteger(n) && n > 0) return n;
  }
  return LEASE_MAX_TTL_SECONDS;
}

export function clampLeaseTtlSeconds(
  requestedSeconds: number,
  maxSeconds: number = localLeaseMaxTtlSeconds(),
): number {
  if (!Number.isFinite(requestedSeconds) || requestedSeconds <= 0) {
    throw new LeaseError("malformed", "lease ttl must be a positive number of seconds");
  }
  if (!Number.isSafeInteger(maxSeconds) || maxSeconds <= 0) {
    throw new LeaseError("malformed", "invalid lease max ttl");
  }
  return Math.min(Math.floor(requestedSeconds), maxSeconds);
}

const LEASE_KEYS = new Set([
  "v",
  "op",
  "leaseId",
  "from",
  "peerId",
  "project",
  "binding",
  "issuedAt",
  "expiresAt",
  "epk",
  "nonce",
  "ct",
  "sig",
]);

/** Strict structural parse (no crypto). Errors never include ciphertext or secrets. */
export function parseSealedLease(raw: unknown): SealedLease {
  const bad = (what: string): never => {
    throw new LeaseError("malformed", `malformed lease: ${what}`);
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) bad("not an object");
  const e = raw as Record<string, unknown>;
  for (const k of Object.keys(e)) {
    if (!LEASE_KEYS.has(k)) bad("unexpected field");
  }
  if (e.v !== LEASE_VERSION) bad("unsupported version");
  if (e.op !== "lease") bad("op");
  if (!isUuid(e.leaseId) || !isUuid(e.from) || !isUuid(e.peerId)) bad("ids");
  if (typeof e.project !== "string" || !e.project.trim()) bad("project");
  if (!isLeaseBinding(e.binding)) bad("binding");
  if (typeof e.issuedAt !== "number" || !Number.isSafeInteger(e.issuedAt) || e.issuedAt < 0) {
    bad("issuedAt");
  }
  if (typeof e.expiresAt !== "number" || !Number.isSafeInteger(e.expiresAt) || e.expiresAt < 0) {
    bad("expiresAt");
  }
  const issuedAt = e.issuedAt as number;
  const expiresAt = e.expiresAt as number;
  if (expiresAt <= issuedAt) bad("expiry");
  if (!strictB64(e.epk, 32)) bad("epk");
  try {
    x25519PublicKey(e.epk as string);
  } catch {
    bad("epk");
  }
  if (!strictB64(e.nonce, NONCE_BYTES)) bad("nonce");
  const ct = strictB64(e.ct, "any");
  if (!ct || ct.length <= GCM_TAG_BYTES) bad("ct");
  if (!strictB64(e.sig, 64)) bad("sig");
  return {
    v: LEASE_VERSION,
    op: "lease",
    leaseId: e.leaseId as string,
    from: e.from as string,
    peerId: e.peerId as string,
    project: (e.project as string).trim(),
    binding: {
      exe: (e.binding as LeaseBinding).exe,
      dev: (e.binding as LeaseBinding).dev,
      ino: (e.binding as LeaseBinding).ino,
    },
    issuedAt: e.issuedAt as number,
    expiresAt: e.expiresAt as number,
    epk: e.epk as string,
    nonce: e.nonce as string,
    ct: e.ct as string,
    sig: e.sig as string,
  };
}

export interface SealLeaseInput {
  /** Hub sync identity (signs the lease). */
  hub: SyncIdentity;
  /** Receiver device public half. */
  peer: { id: string; x25519: string };
  project: string;
  binding: GrantCaller;
  /** Project vars to seal (plaintext only in memory here). */
  vars: Record<string, VarEntry>;
  createdAt?: number;
  ttlSeconds?: number;
  issuedAt?: number;
  leaseId?: string;
  maxTtlSeconds?: number;
}

/** Seal one project's secrets to the receiver device X25519; sign with hub Ed25519. */
export function sealLease(input: SealLeaseInput): SealedLease {
  const project = input.project?.trim();
  if (!project) throw new LeaseError("malformed", "project is required");
  if (!isUuid(input.hub.id) || !isUuid(input.peer.id)) {
    throw new LeaseError("malformed", "lease ids must be UUIDs");
  }
  if (!isLeaseBinding(input.binding)) {
    throw new LeaseError("malformed", "binding must include exe, dev, and ino");
  }
  decodeRawKey(input.peer.x25519);

  const issuedAt = input.issuedAt ?? Date.now();
  const ttl = clampLeaseTtlSeconds(
    input.ttlSeconds ?? LEASE_DEFAULT_TTL_SECONDS,
    input.maxTtlSeconds ?? localLeaseMaxTtlSeconds(),
  );
  const expiresAt = issuedAt + ttl * 1000;
  const createdAt = input.createdAt ?? issuedAt;
  const vars = sanitizeProjectVars(input.vars);

  const eph = crypto.generateKeyPairSync("x25519");
  const header: Omit<SealedLease, "ct" | "sig"> = {
    v: LEASE_VERSION,
    op: "lease",
    leaseId: input.leaseId ?? crypto.randomUUID(),
    from: input.hub.id,
    peerId: input.peer.id,
    project,
    binding: {
      exe: input.binding.exe,
      dev: input.binding.dev,
      ino: input.binding.ino,
    },
    issuedAt,
    expiresAt,
    epk: rawPublicKey(eph.publicKey),
    nonce: crypto.randomBytes(NONCE_BYTES).toString("base64"),
  };

  const payload: LeasePayload = { v: LEASE_VERSION, project, vars, createdAt };
  const shared = crypto.diffieHellman({
    privateKey: eph.privateKey,
    publicKey: x25519PublicKey(input.peer.x25519),
  });
  const key = deriveKey(shared, header, input.peer.x25519);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, Buffer.from(header.nonce, "base64"));
  cipher.setAAD(headerBytes(header));
  const ct = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), "utf8")),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  key.fill(0);
  const sig = crypto.sign(null, sigMessage(header, ct), ed25519PrivateKey(input.hub));

  return {
    ...header,
    ct: ct.toString("base64"),
    sig: sig.toString("base64"),
  };
}

export interface VerifyLeaseOpts {
  now?: number;
  expectedPeerId?: string;
  maxTtlSeconds?: number;
}

/**
 * Verify hub signature, peerId, expiry, and local TTL cap.
 * Does not decrypt. Throws LeaseError — never includes secrets or ciphertext.
 */
export function verifySealedLease(
  lease: SealedLease,
  hubPin: HubPin,
  opts: VerifyLeaseOpts = {},
): void {
  const now = opts.now ?? Date.now();
  if (lease.from !== hubPin.deviceId) {
    throw new LeaseError("wrong-hub", "lease from does not match hub pin");
  }
  if (opts.expectedPeerId !== undefined && lease.peerId !== opts.expectedPeerId) {
    throw new LeaseError("wrong-device", "lease peerId does not match this device");
  }
  if (lease.expiresAt <= now) {
    throw new LeaseError("expired", "lease expired");
  }
  const ttlMs = lease.expiresAt - lease.issuedAt;
  const maxMs = (opts.maxTtlSeconds ?? localLeaseMaxTtlSeconds()) * 1000;
  if (ttlMs > maxMs) {
    throw new LeaseError("ttl-exceeded", "lease ttl exceeds local cap");
  }

  let ok = false;
  try {
    ok = crypto.verify(
      null,
      sigMessage(lease, Buffer.from(lease.ct, "base64")),
      ed25519PublicKey(hubPin.ed25519),
      Buffer.from(lease.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new LeaseError("bad-signature", "lease signature invalid");
}

/** Decrypt a verified lease with the receiver device X25519 key → Project. */
export function openSealedLease(lease: SealedLease, device: DeviceKey): Project {
  if (lease.peerId !== device.id) {
    throw new LeaseError("wrong-device", "lease peerId does not match device key");
  }
  let payload: LeasePayload;
  try {
    const shared = crypto.diffieHellman({
      privateKey: x25519PrivFromDevice(device),
      publicKey: x25519PublicKey(lease.epk),
    });
    const key = deriveKey(shared, lease, device.x25519.publicKey);
    const raw = Buffer.from(lease.ct, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(lease.nonce, "base64"));
    decipher.setAAD(headerBytes(lease));
    decipher.setAuthTag(raw.subarray(raw.length - GCM_TAG_BYTES));
    const plain = Buffer.concat([
      decipher.update(raw.subarray(0, raw.length - GCM_TAG_BYTES)),
      decipher.final(),
    ]);
    key.fill(0);
    payload = JSON.parse(plain.toString("utf8")) as LeasePayload;
  } catch (err) {
    if (err instanceof LeaseError) throw err;
    throw new LeaseError("decrypt-failed", "lease could not be decrypted");
  }
  if (!payload || payload.v !== LEASE_VERSION) {
    throw new LeaseError("decrypt-failed", "unsupported lease payload");
  }
  if (payload.project !== lease.project) {
    throw new LeaseError("wrong-project", "lease payload project mismatch");
  }
  const vars = sanitizeProjectVars(payload.vars);
  return {
    createdAt: typeof payload.createdAt === "number" ? payload.createdAt : lease.issuedAt,
    vars,
  };
}

/** Public metadata only — never secrets. */
export function leasePublicView(lease: SealedLease): {
  leaseId: string;
  peerId: string;
  project: string;
  binding: LeaseBinding;
  issuedAt: number;
  expiresAt: number;
} {
  return {
    leaseId: lease.leaseId,
    peerId: lease.peerId,
    project: lease.project,
    binding: { ...lease.binding },
    issuedAt: lease.issuedAt,
    expiresAt: lease.expiresAt,
  };
}

/**
 * Parse hub lease TTL: `90s`, `30m`, `2h`, `7d`, or plain seconds.
 * Hard-refuses anything above LEASE_HUB_HARD_MAX_TTL_SECONDS (7d) — no clamp.
 */
export function parseLeaseTtl(raw: string): number {
  const s = raw.trim().toLowerCase();
  if (!s) throw new LeaseError("malformed", "ttl is required");

  const m = s.match(/^(\d+(?:\.\d+)?)(s|m|h|d)?$/);
  if (!m) {
    throw new LeaseError(
      "malformed",
      `invalid ttl "${raw}" — use e.g. 90s, 30m, 2h, 7d, or plain seconds`,
    );
  }
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) {
    throw new LeaseError("malformed", `invalid ttl "${raw}"`);
  }
  const unit = m[2] ?? "s";
  let seconds: number;
  switch (unit) {
    case "s":
      seconds = Math.floor(n);
      break;
    case "m":
      seconds = Math.floor(n * 60);
      break;
    case "h":
      seconds = Math.floor(n * 3600);
      break;
    case "d":
      seconds = Math.floor(n * 86400);
      break;
    default:
      throw new LeaseError("malformed", `invalid ttl unit in "${raw}"`);
  }
  if (!Number.isSafeInteger(seconds) || seconds <= 0) {
    throw new LeaseError("malformed", `invalid ttl "${raw}"`);
  }
  if (seconds > LEASE_HUB_HARD_MAX_TTL_SECONDS) {
    throw new LeaseError(
      "ttl-exceeded",
      `lease ttl must be at most ${LEASE_HUB_HARD_MAX_TTL_SECONDS / 86400}d (${LEASE_HUB_HARD_MAX_TTL_SECONDS}s); got ${seconds}s`,
    );
  }
  return seconds;
}

/** Hub → receiver signed lease revoke (no secret material). */
export interface LeaseRevokeRequest {
  v: typeof LEASE_VERSION;
  op: "lease-revoke";
  from: string;
  peerId: string;
  /** Specific lease id, or omit when `all` is true. */
  leaseId?: string;
  /** Revoke every lease on this device from this hub. */
  all?: boolean;
  nonce: string;
  expiresAt: number;
  sig: string;
}

function revokeSigMessage(r: Omit<LeaseRevokeRequest, "sig">): Buffer {
  return lengthPrefixed([
    Buffer.from(SIG_REVOKE_DOMAIN, "utf8"),
    Buffer.from(String(r.v), "utf8"),
    Buffer.from(r.op, "utf8"),
    Buffer.from(r.from, "utf8"),
    Buffer.from(r.peerId, "utf8"),
    Buffer.from(r.leaseId ?? "", "utf8"),
    Buffer.from(r.all ? "1" : "0", "utf8"),
    Buffer.from(r.nonce, "base64"),
    Buffer.from(String(r.expiresAt), "utf8"),
  ]);
}

const REVOKE_KEYS = new Set([
  "v",
  "op",
  "from",
  "peerId",
  "leaseId",
  "all",
  "nonce",
  "expiresAt",
  "sig",
]);

/** Strict structural parse for a lease revoke (no crypto). */
export function parseLeaseRevokeRequest(raw: unknown): LeaseRevokeRequest {
  const bad = (what: string): never => {
    throw new LeaseError("malformed", `malformed lease revoke: ${what}`);
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) bad("not an object");
  const e = raw as Record<string, unknown>;
  for (const k of Object.keys(e)) {
    if (!REVOKE_KEYS.has(k)) bad("unexpected field");
  }
  if (e.v !== LEASE_VERSION) bad("version");
  if (e.op !== "lease-revoke") bad("op");
  if (!isUuid(e.from) || !isUuid(e.peerId)) bad("ids");
  if (typeof e.expiresAt !== "number" || !Number.isSafeInteger(e.expiresAt) || e.expiresAt < 0) {
    bad("expiresAt");
  }
  if (!strictB64(e.nonce, REVOKE_NONCE_BYTES)) bad("nonce");
  if (!strictB64(e.sig, 64)) bad("sig");

  const hasLeaseId = e.leaseId !== undefined;
  const all = e.all === true;
  if (hasLeaseId && all) bad("leaseId+all");
  if (!hasLeaseId && !all) bad("target");
  if (hasLeaseId) {
    if (!isUuid(e.leaseId)) bad("leaseId");
  } else if (e.all !== true) {
    bad("all");
  }

  return {
    v: LEASE_VERSION,
    op: "lease-revoke",
    from: e.from as string,
    peerId: e.peerId as string,
    ...(hasLeaseId ? { leaseId: e.leaseId as string } : {}),
    ...(all ? { all: true } : {}),
    nonce: e.nonce as string,
    expiresAt: e.expiresAt as number,
    sig: e.sig as string,
  };
}

/** Hub: sign a lease revoke for one leaseId or all leases on a device. */
export function buildLeaseRevokeRequest(opts: {
  hub: SyncIdentity;
  peerDeviceId: string;
  leaseId?: string;
  all?: boolean;
  now?: number;
  expiresAt?: number;
  nonce?: Buffer;
}): LeaseRevokeRequest {
  if (!isUuid(opts.peerDeviceId)) {
    throw new LeaseError("malformed", "revoke peer id must be a UUID");
  }
  const all = opts.all === true;
  const leaseId = opts.leaseId;
  if (all === Boolean(leaseId)) {
    throw new LeaseError("malformed", "revoke requires exactly one of leaseId or all");
  }
  if (leaseId !== undefined && !isUuid(leaseId)) {
    throw new LeaseError("malformed", "revoke leaseId must be a UUID");
  }

  const now = opts.now ?? Date.now();
  const expiresAt = opts.expiresAt ?? now + LEASE_REVOKE_TTL_MS;
  if (expiresAt - now > LEASE_REVOKE_TTL_MS) {
    throw new LeaseError("expired", "revoke expiry exceeds 30s maximum");
  }
  if (expiresAt <= now) {
    throw new LeaseError("expired", "revoke expiry is not in the future");
  }

  const nonceBuf = opts.nonce ?? crypto.randomBytes(REVOKE_NONCE_BYTES);
  if (nonceBuf.length !== REVOKE_NONCE_BYTES) {
    throw new LeaseError("malformed", "revoke nonce must be 32 bytes");
  }
  const unsigned: Omit<LeaseRevokeRequest, "sig"> = {
    v: LEASE_VERSION,
    op: "lease-revoke",
    from: opts.hub.id,
    peerId: opts.peerDeviceId,
    ...(leaseId ? { leaseId } : {}),
    ...(all ? { all: true } : {}),
    nonce: nonceBuf.toString("base64"),
    expiresAt,
  };
  const sig = crypto.sign(null, revokeSigMessage(unsigned), ed25519PrivateKey(opts.hub));
  return { ...unsigned, sig: sig.toString("base64") };
}

/** Receiver: verify hub signature + expiry against hub-pin. */
export function verifyLeaseRevokeRequest(
  request: LeaseRevokeRequest,
  hubPin: HubPin,
  opts: { now?: number; expectedPeerId?: string } = {},
): void {
  const now = opts.now ?? Date.now();
  if (request.from !== hubPin.deviceId) {
    throw new LeaseError("wrong-hub", "lease revoke is not from the pinned hub");
  }
  if (opts.expectedPeerId !== undefined && request.peerId !== opts.expectedPeerId) {
    throw new LeaseError("wrong-device", "lease revoke peerId does not match this device");
  }
  if (request.expiresAt <= now) {
    throw new LeaseError("expired", "lease revoke expired");
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      revokeSigMessage(request),
      ed25519PublicKey(hubPin.ed25519),
      Buffer.from(request.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new LeaseError("bad-signature", "lease revoke signature invalid");
}
