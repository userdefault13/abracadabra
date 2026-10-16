import crypto from "node:crypto";
import type { SyncIdentity } from "../core/vault.js";
import {
  decodeRawKey,
  ed25519PrivateKey,
  ed25519PublicKey,
  isUuid,
  lengthPrefixed,
  rawPublicKey,
  x25519PrivateKey,
  x25519PublicKey,
} from "../sync/identity.js";

/**
 * Seal the 32-byte wrap key W to the hub's X25519 key — same construction as
 * sync envelopes (ephemeral X25519 → HKDF → AES-256-GCM + Ed25519 sig), with
 * a dedicated domain so enroll ciphertext cannot be confused with a project seal.
 */

export const ENROLL_SEAL_DOMAIN = "abra-remote-enroll-seal-v1";
const SIG_DOMAIN = `${ENROLL_SEAL_DOMAIN}/sig`;
export const ENROLL_SEAL_VERSION = 1;
const GCM_TAG_BYTES = 16;
const NONCE_BYTES = 12;
const WRAP_KEY_BYTES = 32;

export interface EnrollSealHeader {
  v: typeof ENROLL_SEAL_VERSION;
  from: string;
  to: string;
  offerId: string;
  createdAt: number;
  deviceId: string;
  deviceEd25519: string;
  deviceX25519: string;
  masterKeyFingerprint: string;
  epk: string;
  nonce: string;
}

/** Wire offer: header + sealed W + sender Ed25519 signature. No plaintext W. */
export interface EnrollOffer extends EnrollSealHeader {
  ct: string;
  sig: string;
}

export class EnrollSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnrollSealError";
  }
}

function strictB64(value: unknown, bytes: number | "any"): Buffer | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const buf = Buffer.from(value, "base64");
  if (buf.toString("base64") !== value) return null;
  if (bytes !== "any" && buf.length !== bytes) return null;
  return buf;
}

function headerBytes(h: EnrollSealHeader): Buffer {
  return lengthPrefixed([
    Buffer.from(ENROLL_SEAL_DOMAIN, "utf8"),
    Buffer.from(String(h.v), "utf8"),
    Buffer.from(h.from, "utf8"),
    Buffer.from(h.to, "utf8"),
    Buffer.from(h.offerId, "utf8"),
    Buffer.from(String(h.createdAt), "utf8"),
    Buffer.from(h.deviceId, "utf8"),
    decodeRawKey(h.deviceEd25519),
    decodeRawKey(h.deviceX25519),
    Buffer.from(h.masterKeyFingerprint, "utf8"),
    decodeRawKey(h.epk),
    Buffer.from(h.nonce, "base64"),
  ]);
}

function sigMessage(h: EnrollSealHeader, ct: Buffer): Buffer {
  return lengthPrefixed([Buffer.from(SIG_DOMAIN, "utf8"), headerBytes(h), ct]);
}

function deriveKey(shared: Buffer, h: EnrollSealHeader, recipientX25519: string): Buffer {
  if (shared.every((b) => b === 0)) throw new Error("degenerate X25519 shared secret");
  const info = lengthPrefixed([
    Buffer.from(ENROLL_SEAL_DOMAIN, "utf8"),
    Buffer.from(h.from, "utf8"),
    Buffer.from(h.to, "utf8"),
    decodeRawKey(h.epk),
    decodeRawKey(recipientX25519),
  ]);
  return Buffer.from(
    crypto.hkdfSync("sha256", shared, Buffer.from(ENROLL_SEAL_DOMAIN, "utf8"), info, 32),
  );
}

export interface SealWrapInput {
  /** Receiver sync identity (signs the offer). */
  sender: SyncIdentity;
  /** Hub sync identity id + X25519 pub. */
  hub: { id: string; x25519: string };
  wrapKey: Buffer;
  deviceId: string;
  deviceEd25519: string;
  deviceX25519: string;
  masterKeyFingerprint: string;
  now?: number;
  offerId?: string;
}

/** Seal W to the hub. Caller must zero `wrapKey` after this returns. */
export function sealWrapKeyForHub(input: SealWrapInput): EnrollOffer {
  const { sender, hub, wrapKey } = input;
  if (!Buffer.isBuffer(wrapKey) || wrapKey.length !== WRAP_KEY_BYTES) {
    throw new Error("wrap key must be 32 bytes");
  }
  if (!isUuid(input.deviceId) || !isUuid(hub.id) || !isUuid(sender.id)) {
    throw new Error("enroll ids must be UUIDs");
  }
  decodeRawKey(hub.x25519);
  decodeRawKey(input.deviceEd25519);
  decodeRawKey(input.deviceX25519);

  const eph = crypto.generateKeyPairSync("x25519");
  const header: EnrollSealHeader = {
    v: ENROLL_SEAL_VERSION,
    from: sender.id,
    to: hub.id,
    offerId: input.offerId ?? crypto.randomUUID(),
    createdAt: input.now ?? Date.now(),
    deviceId: input.deviceId,
    deviceEd25519: input.deviceEd25519,
    deviceX25519: input.deviceX25519,
    masterKeyFingerprint: input.masterKeyFingerprint,
    epk: rawPublicKey(eph.publicKey),
    nonce: crypto.randomBytes(NONCE_BYTES).toString("base64"),
  };

  const shared = crypto.diffieHellman({
    privateKey: eph.privateKey,
    publicKey: x25519PublicKey(hub.x25519),
  });
  const key = deriveKey(shared, header, hub.x25519);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, Buffer.from(header.nonce, "base64"));
  cipher.setAAD(headerBytes(header));
  const ct = Buffer.concat([cipher.update(wrapKey), cipher.final(), cipher.getAuthTag()]);
  key.fill(0);
  const sig = crypto.sign(null, sigMessage(header, ct), ed25519PrivateKey(sender));

  return {
    ...header,
    ct: ct.toString("base64"),
    sig: sig.toString("base64"),
  };
}

const OFFER_KEYS = new Set([
  "v",
  "from",
  "to",
  "offerId",
  "createdAt",
  "deviceId",
  "deviceEd25519",
  "deviceX25519",
  "masterKeyFingerprint",
  "epk",
  "nonce",
  "ct",
  "sig",
]);

/** Strict structural parse (no crypto). */
export function parseEnrollOffer(raw: unknown): EnrollOffer {
  const bad = (what: string): never => {
    throw new EnrollSealError(`malformed enroll offer: ${what}`);
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) bad("not an object");
  const e = raw as Record<string, unknown>;
  for (const k of Object.keys(e)) {
    if (!OFFER_KEYS.has(k)) bad(`unexpected field ${JSON.stringify(k.slice(0, 32))}`);
  }
  if (e.v !== ENROLL_SEAL_VERSION) bad("unsupported version");
  if (!isUuid(e.from) || !isUuid(e.to) || !isUuid(e.offerId) || !isUuid(e.deviceId)) bad("ids");
  if (typeof e.createdAt !== "number" || !Number.isSafeInteger(e.createdAt) || e.createdAt < 0) {
    bad("createdAt");
  }
  if (typeof e.masterKeyFingerprint !== "string" || e.masterKeyFingerprint.length === 0) {
    bad("masterKeyFingerprint");
  }
  for (const k of ["deviceEd25519", "deviceX25519", "epk"] as const) {
    if (!strictB64(e[k], 32)) bad(k);
    try {
      if (k === "epk" || k === "deviceX25519") x25519PublicKey(e[k] as string);
      else ed25519PublicKey(e[k] as string);
    } catch {
      bad(k);
    }
  }
  if (!strictB64(e.nonce, NONCE_BYTES)) bad("nonce");
  const ct = strictB64(e.ct, "any");
  if (!ct || ct.length <= GCM_TAG_BYTES) bad("ct");
  if (!strictB64(e.sig, 64)) bad("sig");
  return {
    v: ENROLL_SEAL_VERSION,
    from: e.from as string,
    to: e.to as string,
    offerId: e.offerId as string,
    createdAt: e.createdAt as number,
    deviceId: e.deviceId as string,
    deviceEd25519: e.deviceEd25519 as string,
    deviceX25519: e.deviceX25519 as string,
    masterKeyFingerprint: e.masterKeyFingerprint as string,
    epk: e.epk as string,
    nonce: e.nonce as string,
    ct: e.ct as string,
    sig: e.sig as string,
  };
}

/**
 * Verify Ed25519 signature against the pinned peer ed25519 pub, then decrypt W
 * with the hub identity's X25519 private key. Returns a fresh Buffer — zero it
 * after storing in the vault.
 */
export function openWrapKeyFromOffer(
  offer: EnrollOffer,
  hubIdentity: SyncIdentity,
  senderEd25519: string,
): Buffer {
  if (offer.to !== hubIdentity.id) {
    throw new EnrollSealError("enroll offer is addressed to another identity");
  }

  let ok = false;
  try {
    ok = crypto.verify(
      null,
      sigMessage(offer, Buffer.from(offer.ct, "base64")),
      ed25519PublicKey(senderEd25519),
      Buffer.from(offer.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new EnrollSealError("enroll offer signature does not match the pinned peer key");

  try {
    const shared = crypto.diffieHellman({
      privateKey: x25519PrivateKey(hubIdentity),
      publicKey: x25519PublicKey(offer.epk),
    });
    const key = deriveKey(shared, offer, hubIdentity.x25519.publicKey);
    const raw = Buffer.from(offer.ct, "base64");
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(offer.nonce, "base64"),
    );
    decipher.setAAD(headerBytes(offer));
    decipher.setAuthTag(raw.subarray(raw.length - GCM_TAG_BYTES));
    const plain = Buffer.concat([
      decipher.update(raw.subarray(0, raw.length - GCM_TAG_BYTES)),
      decipher.final(),
    ]);
    key.fill(0);
    if (plain.length !== WRAP_KEY_BYTES) {
      plain.fill(0);
      throw new EnrollSealError("enroll offer decrypted to unexpected length");
    }
    return plain;
  } catch (err) {
    if (err instanceof EnrollSealError) throw err;
    throw new EnrollSealError("enroll offer could not be decrypted");
  }
}
