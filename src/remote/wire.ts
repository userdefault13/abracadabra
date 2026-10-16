import crypto, { type KeyObject } from "node:crypto";
import type { SyncIdentity, UnlockWrap } from "../core/vault.js";
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
 * Remote-unlock challenge/response wire crypto (PR 3).
 *
 * 1. Receiver → hub: nonce (32B) + ephemeral X25519 pub, signed with device key
 * 2. Hub → receiver: seal(ephemeral_pub, W) + Ed25519 over
 *    (from, peerId, nonce, expiresAt ≤ 30s, policy, seal fields)
 * 3. Receiver verifies hub-pin, expiry, single-use nonce; unwraps; unlocks
 *
 * No secret values in errors. Domain separated from enroll / sync seals.
 */

export const UNLOCK_WIRE_DOMAIN = "abra-remote-unlock-wire-v1";
const SIG_CHALLENGE_DOMAIN = `${UNLOCK_WIRE_DOMAIN}/challenge-sig`;
const SIG_RESPONSE_DOMAIN = `${UNLOCK_WIRE_DOMAIN}/response-sig`;
const SEAL_DOMAIN = `${UNLOCK_WIRE_DOMAIN}/seal`;

export const UNLOCK_WIRE_VERSION = 1;
export const CHALLENGE_NONCE_BYTES = 32;
export const MAX_RESPONSE_TTL_MS = 30_000;
export const UNLOCK_MAX_BODY_BYTES = 8 * 1024;
export const UNLOCK_PATH = "/v1/remote/unlock";
export const LOCK_PATH = "/v1/remote/lock";
export const STATUS_PATH = "/v1/remote/status";
export const ENROLL_PATH = "/v1/remote/enroll";
export const REMOTE_UNLOCK_PORT = 7335;

const SIG_LOCK_DOMAIN = `${UNLOCK_WIRE_DOMAIN}/lock-sig`;

const GCM_TAG_BYTES = 16;
const SEAL_NONCE_BYTES = 12;
const WRAP_KEY_BYTES = 32;

export interface UnlockPolicy {
  /** Hint only in PR 3; local caps applied in PR 5. */
  idleSeconds?: number;
  maxAgeSeconds?: number;
}

export interface UnlockChallenge {
  v: typeof UNLOCK_WIRE_VERSION;
  op: "challenge";
  /** Receiver device-key id. */
  deviceId: string;
  /** base64 raw 32-byte challenge nonce */
  nonce: string;
  /** base64 raw 32-byte ephemeral X25519 public key */
  epk: string;
  createdAt: number;
  /** base64 Ed25519 signature */
  sig: string;
}

export interface UnlockResponse {
  v: typeof UNLOCK_WIRE_VERSION;
  op: "response";
  /** Hub sync / pin id (must match hub-pin.deviceId). */
  from: string;
  /** Receiver device-key id (must match challenge / unlockWrap.deviceId). */
  peerId: string;
  nonce: string;
  expiresAt: number;
  policy: UnlockPolicy;
  /** Hub seal ephemeral X25519 pub */
  epk: string;
  /** AES-GCM nonce (12 bytes) */
  sealNonce: string;
  /** ciphertext ‖ tag of W */
  ct: string;
  sig: string;
}

export type UnlockWireMessage = UnlockChallenge | UnlockResponse;

/** Hub → receiver signed lock (no Touch ID; no wrap key). */
export interface LockRequest {
  v: typeof UNLOCK_WIRE_VERSION;
  op: "lock";
  /** Hub sync / pin id. */
  from: string;
  /** Receiver device-key id. */
  peerId: string;
  /** base64 raw 32-byte nonce */
  nonce: string;
  expiresAt: number;
  sig: string;
}

export class UnlockWireError extends Error {
  constructor(
    readonly reason:
      | "malformed"
      | "bad-signature"
      | "expired"
      | "replay"
      | "wrong-hub"
      | "wrong-device"
      | "decrypt-failed"
      | "stale-challenge",
    message: string,
  ) {
    super(message);
    this.name = "UnlockWireError";
  }
}

function b64url(b64: string): string {
  return Buffer.from(b64, "base64").toString("base64url");
}

function strictB64(value: unknown, bytes: number | "any"): Buffer | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const buf = Buffer.from(value, "base64");
  if (buf.toString("base64") !== value) return null;
  if (bytes !== "any" && buf.length !== bytes) return null;
  return buf;
}

function ed25519PrivFromPair(pair: { publicKey: string; privateKey: string }): KeyObject {
  decodeRawKey(pair.publicKey);
  decodeRawKey(pair.privateKey);
  return crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: b64url(pair.publicKey),
      d: b64url(pair.privateKey),
    },
    format: "jwk",
  });
}

function x25519PrivFromRaw(publicB64: string, privateRaw: Buffer): KeyObject {
  decodeRawKey(publicB64);
  if (privateRaw.length !== 32) throw new Error("x25519 private key must be 32 bytes");
  return crypto.createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      x: b64url(publicB64),
      d: privateRaw.toString("base64url"),
    },
    format: "jwk",
  });
}

function exportRawD(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" }) as { d?: string };
  if (!jwk.d) throw new Error("missing private key material");
  return Buffer.from(jwk.d, "base64url");
}

function policyBytes(policy: UnlockPolicy): Buffer {
  const idle = policy.idleSeconds ?? "";
  const maxAge = policy.maxAgeSeconds ?? "";
  return lengthPrefixed([
    Buffer.from(String(idle), "utf8"),
    Buffer.from(String(maxAge), "utf8"),
  ]);
}

function challengeSigMessage(c: Omit<UnlockChallenge, "sig">): Buffer {
  return lengthPrefixed([
    Buffer.from(SIG_CHALLENGE_DOMAIN, "utf8"),
    Buffer.from(String(c.v), "utf8"),
    Buffer.from(c.deviceId, "utf8"),
    Buffer.from(c.nonce, "base64"),
    decodeRawKey(c.epk),
    Buffer.from(String(c.createdAt), "utf8"),
  ]);
}

function responseSigMessage(r: Omit<UnlockResponse, "sig">): Buffer {
  return lengthPrefixed([
    Buffer.from(SIG_RESPONSE_DOMAIN, "utf8"),
    Buffer.from(String(r.v), "utf8"),
    Buffer.from(r.from, "utf8"),
    Buffer.from(r.peerId, "utf8"),
    Buffer.from(r.nonce, "base64"),
    Buffer.from(String(r.expiresAt), "utf8"),
    policyBytes(r.policy),
    decodeRawKey(r.epk),
    Buffer.from(r.sealNonce, "base64"),
    Buffer.from(r.ct, "base64"),
  ]);
}

function sealHeaderBytes(opts: {
  from: string;
  peerId: string;
  nonce: string;
  expiresAt: number;
  policy: UnlockPolicy;
  epk: string;
  sealNonce: string;
}): Buffer {
  return lengthPrefixed([
    Buffer.from(SEAL_DOMAIN, "utf8"),
    Buffer.from(opts.from, "utf8"),
    Buffer.from(opts.peerId, "utf8"),
    Buffer.from(opts.nonce, "base64"),
    Buffer.from(String(opts.expiresAt), "utf8"),
    policyBytes(opts.policy),
    decodeRawKey(opts.epk),
    Buffer.from(opts.sealNonce, "base64"),
  ]);
}

function deriveSealKey(
  shared: Buffer,
  opts: { from: string; peerId: string; nonce: string; epk: string; recipientEpk: string },
): Buffer {
  if (shared.every((b) => b === 0)) throw new Error("degenerate X25519 shared secret");
  const info = lengthPrefixed([
    Buffer.from(SEAL_DOMAIN, "utf8"),
    Buffer.from(opts.from, "utf8"),
    Buffer.from(opts.peerId, "utf8"),
    Buffer.from(opts.nonce, "base64"),
    decodeRawKey(opts.epk),
    decodeRawKey(opts.recipientEpk),
  ]);
  return Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(SEAL_DOMAIN, "utf8"), info, 32));
}

function parsePolicy(raw: unknown): UnlockPolicy {
  if (raw === undefined || raw === null) return {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new UnlockWireError("malformed", "malformed unlock policy");
  }
  const p = raw as Record<string, unknown>;
  for (const k of Object.keys(p)) {
    if (k !== "idleSeconds" && k !== "maxAgeSeconds") {
      throw new UnlockWireError("malformed", "malformed unlock policy");
    }
  }
  const out: UnlockPolicy = {};
  if (p.idleSeconds !== undefined) {
    if (typeof p.idleSeconds !== "number" || !Number.isSafeInteger(p.idleSeconds) || p.idleSeconds < 0) {
      throw new UnlockWireError("malformed", "malformed unlock policy");
    }
    out.idleSeconds = p.idleSeconds;
  }
  if (p.maxAgeSeconds !== undefined) {
    if (
      typeof p.maxAgeSeconds !== "number" ||
      !Number.isSafeInteger(p.maxAgeSeconds) ||
      p.maxAgeSeconds < 0
    ) {
      throw new UnlockWireError("malformed", "malformed unlock policy");
    }
    out.maxAgeSeconds = p.maxAgeSeconds;
  }
  return out;
}

const CHALLENGE_KEYS = new Set(["v", "op", "deviceId", "nonce", "epk", "createdAt", "sig"]);
const RESPONSE_KEYS = new Set([
  "v",
  "op",
  "from",
  "peerId",
  "nonce",
  "expiresAt",
  "policy",
  "epk",
  "sealNonce",
  "ct",
  "sig",
]);

/** Strict structural parse (no crypto). */
export function parseUnlockWireMessage(raw: unknown): UnlockWireMessage {
  const bad = (): never => {
    throw new UnlockWireError("malformed", "malformed unlock wire message");
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) bad();
  const e = raw as Record<string, unknown>;
  if (e.v !== UNLOCK_WIRE_VERSION) bad();
  if (e.op === "challenge") {
    for (const k of Object.keys(e)) {
      if (!CHALLENGE_KEYS.has(k)) bad();
    }
    if (!isUuid(e.deviceId)) bad();
    if (typeof e.createdAt !== "number" || !Number.isSafeInteger(e.createdAt) || e.createdAt < 0) bad();
    if (!strictB64(e.nonce, CHALLENGE_NONCE_BYTES)) bad();
    if (!strictB64(e.epk, 32)) bad();
    try {
      x25519PublicKey(e.epk as string);
    } catch {
      bad();
    }
    if (!strictB64(e.sig, 64)) bad();
    return {
      v: UNLOCK_WIRE_VERSION,
      op: "challenge",
      deviceId: e.deviceId as string,
      nonce: e.nonce as string,
      epk: e.epk as string,
      createdAt: e.createdAt as number,
      sig: e.sig as string,
    };
  }
  if (e.op === "response") {
    for (const k of Object.keys(e)) {
      if (!RESPONSE_KEYS.has(k)) bad();
    }
    if (!isUuid(e.from) || !isUuid(e.peerId)) bad();
    if (typeof e.expiresAt !== "number" || !Number.isSafeInteger(e.expiresAt) || e.expiresAt < 0) bad();
    if (!strictB64(e.nonce, CHALLENGE_NONCE_BYTES)) bad();
    if (!strictB64(e.epk, 32) || !strictB64(e.sealNonce, SEAL_NONCE_BYTES)) bad();
    try {
      x25519PublicKey(e.epk as string);
    } catch {
      bad();
    }
    const ct = strictB64(e.ct, "any");
    if (!ct || ct.length <= GCM_TAG_BYTES) bad();
    if (!strictB64(e.sig, 64)) bad();
    const policy = parsePolicy(e.policy);
    return {
      v: UNLOCK_WIRE_VERSION,
      op: "response",
      from: e.from as string,
      peerId: e.peerId as string,
      nonce: e.nonce as string,
      expiresAt: e.expiresAt as number,
      policy,
      epk: e.epk as string,
      sealNonce: e.sealNonce as string,
      ct: e.ct as string,
      sig: e.sig as string,
    };
  }
  return bad();
}

export interface IssuedChallenge {
  message: UnlockChallenge;
  /** Raw 32-byte ephemeral private scalar — store in NonceCache; zero after redeem. */
  ephPrivateRaw: Buffer;
}

/** Receiver: mint a signed challenge. */
export function issueUnlockChallenge(
  deviceKey: DeviceKey,
  opts: { now?: number; nonce?: Buffer } = {},
): IssuedChallenge {
  const now = opts.now ?? Date.now();
  const nonceBuf = opts.nonce ?? crypto.randomBytes(CHALLENGE_NONCE_BYTES);
  if (nonceBuf.length !== CHALLENGE_NONCE_BYTES) throw new Error("challenge nonce must be 32 bytes");

  const eph = crypto.generateKeyPairSync("x25519");
  const epk = rawPublicKey(eph.publicKey);
  const ephPrivateRaw = exportRawD(eph.privateKey);

  const unsigned: Omit<UnlockChallenge, "sig"> = {
    v: UNLOCK_WIRE_VERSION,
    op: "challenge",
    deviceId: deviceKey.id,
    nonce: nonceBuf.toString("base64"),
    epk,
    createdAt: now,
  };
  const sig = crypto.sign(null, challengeSigMessage(unsigned), ed25519PrivFromPair(deviceKey.ed25519));
  return {
    message: { ...unsigned, sig: sig.toString("base64") },
    ephPrivateRaw,
  };
}

/** Hub: verify challenge against the enrolled device public key. */
export function verifyUnlockChallenge(
  challenge: UnlockChallenge,
  deviceEd25519: string,
  opts: { expectedDeviceId?: string } = {},
): void {
  if (opts.expectedDeviceId !== undefined && challenge.deviceId !== opts.expectedDeviceId) {
    throw new UnlockWireError("wrong-device", "challenge device id does not match enrollment");
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      challengeSigMessage(challenge),
      ed25519PublicKey(deviceEd25519),
      Buffer.from(challenge.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new UnlockWireError("bad-signature", "challenge signature does not match device key");
}

export interface BuildUnlockResponseInput {
  hubIdentity: SyncIdentity;
  /** Enrolled wrap record (W + device pubs). */
  unlockWrap: UnlockWrap;
  challenge: UnlockChallenge;
  policy?: UnlockPolicy;
  now?: number;
  /** Override expiry (tests). Default: now + 30s. */
  expiresAt?: number;
}

/**
 * Hub: seal W to the challenge ephemeral pub and sign the response.
 * Zeros a copy of W after sealing; does not mutate unlockWrap.wrapKey string.
 */
export function buildUnlockResponse(input: BuildUnlockResponseInput): UnlockResponse {
  const { hubIdentity, unlockWrap, challenge } = input;
  verifyUnlockChallenge(challenge, unlockWrap.deviceEd25519, {
    expectedDeviceId: unlockWrap.deviceId,
  });

  const now = input.now ?? Date.now();
  const expiresAt = input.expiresAt ?? now + MAX_RESPONSE_TTL_MS;
  if (expiresAt - now > MAX_RESPONSE_TTL_MS) {
    throw new UnlockWireError("expired", "response expiry exceeds 30s maximum");
  }
  if (expiresAt <= now) {
    throw new UnlockWireError("expired", "response expiry is not in the future");
  }

  const policy = input.policy ?? {};
  const wrapKey = decodeRawKey(unlockWrap.wrapKey);
  let ct: Buffer;
  let epk: string;
  let sealNonce: string;
  try {
    const eph = crypto.generateKeyPairSync("x25519");
    epk = rawPublicKey(eph.publicKey);
    sealNonce = crypto.randomBytes(SEAL_NONCE_BYTES).toString("base64");
    const shared = crypto.diffieHellman({
      privateKey: eph.privateKey,
      publicKey: x25519PublicKey(challenge.epk),
    });
    const key = deriveSealKey(shared, {
      from: hubIdentity.id,
      peerId: unlockWrap.deviceId,
      nonce: challenge.nonce,
      epk,
      recipientEpk: challenge.epk,
    });
    const header = sealHeaderBytes({
      from: hubIdentity.id,
      peerId: unlockWrap.deviceId,
      nonce: challenge.nonce,
      expiresAt,
      policy,
      epk,
      sealNonce,
    });
    const cipher = crypto.createCipheriv("aes-256-gcm", key, Buffer.from(sealNonce, "base64"));
    cipher.setAAD(header);
    ct = Buffer.concat([cipher.update(wrapKey), cipher.final(), cipher.getAuthTag()]);
    key.fill(0);
  } finally {
    wrapKey.fill(0);
  }

  const unsigned: Omit<UnlockResponse, "sig"> = {
    v: UNLOCK_WIRE_VERSION,
    op: "response",
    from: hubIdentity.id,
    peerId: unlockWrap.deviceId,
    nonce: challenge.nonce,
    expiresAt,
    policy,
    epk,
    sealNonce,
    ct: ct.toString("base64"),
  };
  const sig = crypto.sign(null, responseSigMessage(unsigned), ed25519PrivateKey(hubIdentity));
  return { ...unsigned, sig: sig.toString("base64") };
}

/**
 * Receiver: verify hub signature + expiry. Does not decrypt.
 * `now` must be ≤ expiresAt and expiresAt − issued ≤ 30s from challenge time is
 * enforced as expiresAt − now ∈ (0, 30s] relative to receiver clock (plus the
 * absolute TTL cap already applied by the hub).
 */
export function verifyUnlockResponse(
  response: UnlockResponse,
  hubPin: HubPin,
  opts: { now?: number; expectedPeerId?: string } = {},
): void {
  const now = opts.now ?? Date.now();
  if (response.from !== hubPin.deviceId) {
    throw new UnlockWireError("wrong-hub", "response is not from the pinned hub");
  }
  if (opts.expectedPeerId !== undefined && response.peerId !== opts.expectedPeerId) {
    throw new UnlockWireError("wrong-device", "response peer id does not match this device");
  }
  if (response.expiresAt <= now) {
    throw new UnlockWireError("expired", "unlock response has expired");
  }
  if (response.expiresAt - now > MAX_RESPONSE_TTL_MS) {
    throw new UnlockWireError("expired", "unlock response expiry exceeds 30s");
  }

  let ok = false;
  try {
    ok = crypto.verify(
      null,
      responseSigMessage(response),
      ed25519PublicKey(hubPin.ed25519),
      Buffer.from(response.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new UnlockWireError("bad-signature", "response signature does not match hub pin");
}

/**
 * Decrypt W from a verified response using the challenge ephemeral private key.
 * Returns a fresh 32-byte Buffer — caller must zero it after unwrapping the blob.
 */
export function openWrapKeyFromResponse(
  response: UnlockResponse,
  challengeEpk: string,
  challengeEphPrivateRaw: Buffer,
): Buffer {
  try {
    const shared = crypto.diffieHellman({
      privateKey: x25519PrivFromRaw(challengeEpk, challengeEphPrivateRaw),
      publicKey: x25519PublicKey(response.epk),
    });
    const key = deriveSealKey(shared, {
      from: response.from,
      peerId: response.peerId,
      nonce: response.nonce,
      epk: response.epk,
      recipientEpk: challengeEpk,
    });
    const header = sealHeaderBytes({
      from: response.from,
      peerId: response.peerId,
      nonce: response.nonce,
      expiresAt: response.expiresAt,
      policy: response.policy,
      epk: response.epk,
      sealNonce: response.sealNonce,
    });
    const raw = Buffer.from(response.ct, "base64");
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(response.sealNonce, "base64"),
    );
    decipher.setAAD(header);
    decipher.setAuthTag(raw.subarray(raw.length - GCM_TAG_BYTES));
    const plain = Buffer.concat([
      decipher.update(raw.subarray(0, raw.length - GCM_TAG_BYTES)),
      decipher.final(),
    ]);
    key.fill(0);
    if (plain.length !== WRAP_KEY_BYTES) {
      plain.fill(0);
      throw new UnlockWireError("decrypt-failed", "unlock seal decrypted to unexpected length");
    }
    return plain;
  } catch (err) {
    if (err instanceof UnlockWireError) throw err;
    throw new UnlockWireError("decrypt-failed", "unlock seal could not be decrypted");
  }
}

function lockSigMessage(r: Omit<LockRequest, "sig">): Buffer {
  return lengthPrefixed([
    Buffer.from(SIG_LOCK_DOMAIN, "utf8"),
    Buffer.from(String(r.v), "utf8"),
    Buffer.from(r.from, "utf8"),
    Buffer.from(r.peerId, "utf8"),
    Buffer.from(r.nonce, "base64"),
    Buffer.from(String(r.expiresAt), "utf8"),
  ]);
}

const LOCK_KEYS = new Set(["v", "op", "from", "peerId", "nonce", "expiresAt", "sig"]);

/** Strict structural parse for a lock request (no crypto). */
export function parseLockRequest(raw: unknown): LockRequest {
  const bad = (): never => {
    throw new UnlockWireError("malformed", "malformed lock request");
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) bad();
  const e = raw as Record<string, unknown>;
  if (e.v !== UNLOCK_WIRE_VERSION || e.op !== "lock") bad();
  for (const k of Object.keys(e)) {
    if (!LOCK_KEYS.has(k)) bad();
  }
  if (!isUuid(e.from) || !isUuid(e.peerId)) bad();
  if (typeof e.expiresAt !== "number" || !Number.isSafeInteger(e.expiresAt) || e.expiresAt < 0) bad();
  if (!strictB64(e.nonce, CHALLENGE_NONCE_BYTES)) bad();
  if (!strictB64(e.sig, 64)) bad();
  return {
    v: UNLOCK_WIRE_VERSION,
    op: "lock",
    from: e.from as string,
    peerId: e.peerId as string,
    nonce: e.nonce as string,
    expiresAt: e.expiresAt as number,
    sig: e.sig as string,
  };
}

/** Hub: sign a lock request for a receiver device id. */
export function buildLockRequest(opts: {
  hubIdentity: SyncIdentity;
  peerDeviceId: string;
  now?: number;
  expiresAt?: number;
  nonce?: Buffer;
}): LockRequest {
  const now = opts.now ?? Date.now();
  const expiresAt = opts.expiresAt ?? now + MAX_RESPONSE_TTL_MS;
  if (expiresAt - now > MAX_RESPONSE_TTL_MS) {
    throw new UnlockWireError("expired", "lock expiry exceeds 30s maximum");
  }
  if (expiresAt <= now) {
    throw new UnlockWireError("expired", "lock expiry is not in the future");
  }
  if (!isUuid(opts.peerDeviceId)) {
    throw new UnlockWireError("malformed", "lock peer id must be a UUID");
  }
  const nonceBuf = opts.nonce ?? crypto.randomBytes(CHALLENGE_NONCE_BYTES);
  if (nonceBuf.length !== CHALLENGE_NONCE_BYTES) throw new Error("lock nonce must be 32 bytes");
  const unsigned: Omit<LockRequest, "sig"> = {
    v: UNLOCK_WIRE_VERSION,
    op: "lock",
    from: opts.hubIdentity.id,
    peerId: opts.peerDeviceId,
    nonce: nonceBuf.toString("base64"),
    expiresAt,
  };
  const sig = crypto.sign(null, lockSigMessage(unsigned), ed25519PrivateKey(opts.hubIdentity));
  return { ...unsigned, sig: sig.toString("base64") };
}

/** Receiver: verify hub signature + expiry against hub-pin. */
export function verifyLockRequest(
  request: LockRequest,
  hubPin: HubPin,
  opts: { now?: number; expectedPeerId?: string } = {},
): void {
  const now = opts.now ?? Date.now();
  if (request.from !== hubPin.deviceId) {
    throw new UnlockWireError("wrong-hub", "lock request is not from the pinned hub");
  }
  if (opts.expectedPeerId !== undefined && request.peerId !== opts.expectedPeerId) {
    throw new UnlockWireError("wrong-device", "lock request peer id does not match this device");
  }
  if (request.expiresAt <= now) {
    throw new UnlockWireError("expired", "lock request has expired");
  }
  if (request.expiresAt - now > MAX_RESPONSE_TTL_MS) {
    throw new UnlockWireError("expired", "lock request expiry exceeds 30s");
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      lockSigMessage(request),
      ed25519PublicKey(hubPin.ed25519),
      Buffer.from(request.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new UnlockWireError("bad-signature", "lock signature does not match hub pin");
}
