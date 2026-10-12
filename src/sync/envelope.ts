import crypto from "node:crypto";
import type { Project, SyncIdentity, SyncPeerRole, Vault, VarEntry } from "../core/vault.js";
import { assertScopeNamesAllowed, extractScopedProjects, validateScope } from "../core/sync-scope.js";
import {
  decodeRawKey,
  ed25519PrivateKey,
  ed25519PublicKey,
  isUuid,
  lengthPrefixed,
  rawPublicKey,
  x25519PrivateKey,
  x25519PublicKey,
} from "./identity.js";
import { findPeer } from "./peers.js";

/**
 * Sealed-to-key sync bundle (abra-sync-seal-v1).
 *
 * The source seals a scoped payload (projects only) to ONE receiver's pinned
 * X25519 key and signs it with its Ed25519 identity key:
 *
 *   shared = X25519(ephemeral, receiver.x25519)
 *   key    = HKDF-SHA256(shared, salt "abra-sync-seal-v1",
 *                        info = lp("abra-sync-seal-v1", from, to, epk, receiver.x25519))
 *   ct     = AES-256-GCM(key, nonce, payload, aad = header bytes) ‖ tag
 *   sig    = Ed25519(sender, lp("abra-sync-seal-v1/sig", header bytes, ct))
 *
 * `lp` = u32-BE length-prefixed concatenation. Header bytes cover v, from, to,
 * bundleId, createdAt, projects, epk and nonce — so any header edit breaks both
 * the signature and the GCM tag.
 */

export const SEAL_DOMAIN = "abra-sync-seal-v1";
const SIG_DOMAIN = `${SEAL_DOMAIN}/sig`;
export const ENVELOPE_VERSION = 1;
/** createdAt must be within ±10 min of the receiver's clock at receive time. */
export const MAX_CLOCK_SKEW_MS = 10 * 60_000;
export const MAX_ENVELOPE_PROJECTS = 256;
const GCM_TAG_BYTES = 16;
const NONCE_BYTES = 12;

export interface EnvelopeHeader {
  v: typeof ENVELOPE_VERSION;
  from: string;
  to: string;
  bundleId: string;
  createdAt: number;
  projects: string[];
  /** Ephemeral X25519 public key, base64 raw 32 bytes. */
  epk: string;
  /** AES-GCM nonce, base64 of 12 bytes. */
  nonce: string;
}

export interface SealedEnvelope extends EnvelopeHeader {
  /** base64 ciphertext ‖ 16-byte GCM tag */
  ct: string;
  /** base64 Ed25519 signature over header + ct */
  sig: string;
}

interface SealedPayload {
  v: typeof ENVELOPE_VERSION;
  projects: Record<string, Project>;
}

export type EnvelopeRejectReason =
  | "malformed"
  | "wrong-recipient"
  | "unknown-sender"
  | "sender-not-source"
  | "bad-signature"
  | "stale"
  | "replay"
  | "bad-projects"
  | "decrypt-failed";

export class EnvelopeError extends Error {
  constructor(
    readonly reason: EnvelopeRejectReason,
    message: string,
  ) {
    super(message);
    this.name = "EnvelopeError";
  }
}

/** Pinned keys a receiver checks envelopes against (vault, or the inbox mirror while locked). */
export interface EnvelopeTrust {
  myId: string;
  peers: Record<string, { name: string; ed25519: string; role: SyncPeerRole }>;
}

export function trustFromVault(vault: Vault): EnvelopeTrust | null {
  if (!vault.syncIdentity) return null;
  return { myId: vault.syncIdentity.id, peers: vault.syncPeers ?? {} };
}

function strictB64(value: unknown, bytes: number | "any"): Buffer | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const buf = Buffer.from(value, "base64");
  if (buf.toString("base64") !== value) return null;
  if (bytes !== "any" && buf.length !== bytes) return null;
  return buf;
}

function headerBytes(h: EnvelopeHeader): Buffer {
  return lengthPrefixed([
    Buffer.from(SEAL_DOMAIN, "utf8"),
    Buffer.from(String(h.v), "utf8"),
    Buffer.from(h.from, "utf8"),
    Buffer.from(h.to, "utf8"),
    Buffer.from(h.bundleId, "utf8"),
    Buffer.from(String(h.createdAt), "utf8"),
    lengthPrefixed(h.projects.map((p) => Buffer.from(p, "utf8"))),
    decodeRawKey(h.epk),
    Buffer.from(h.nonce, "base64"),
  ]);
}

/** Exact bytes the sender's Ed25519 key signs (header + ct). */
export function sigMessage(h: EnvelopeHeader, ct: Buffer): Buffer {
  return lengthPrefixed([Buffer.from(SIG_DOMAIN, "utf8"), headerBytes(h), ct]);
}

function deriveKey(shared: Buffer, h: EnvelopeHeader, recipientX25519: string): Buffer {
  if (shared.every((b) => b === 0)) throw new Error("degenerate X25519 shared secret");
  const info = lengthPrefixed([
    Buffer.from(SEAL_DOMAIN, "utf8"),
    Buffer.from(h.from, "utf8"),
    Buffer.from(h.to, "utf8"),
    decodeRawKey(h.epk),
    decodeRawKey(recipientX25519),
  ]);
  return Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(SEAL_DOMAIN, "utf8"), info, 32));
}

/** Deduped/trimmed names must equal the given list exactly (no reserved, no duplicates). */
function checkProjectNames(names: string[]): string[] {
  if (names.length > MAX_ENVELOPE_PROJECTS) {
    throw new EnvelopeError("bad-projects", `too many projects (max ${MAX_ENVELOPE_PROJECTS})`);
  }
  let cleaned: string[];
  try {
    cleaned = assertScopeNamesAllowed(names);
  } catch (err) {
    throw new EnvelopeError("bad-projects", err instanceof Error ? err.message : String(err));
  }
  if (cleaned.length !== names.length || cleaned.some((n, i) => n !== names[i] || n === "__proto__")) {
    throw new EnvelopeError("bad-projects", "project names must be unique, trimmed and not reserved");
  }
  return cleaned;
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
    throw new Error("malformed var entry");
  }
  return { value: e.value, secret: e.secret, updatedAt: e.updatedAt };
}

/** Rebuild projects from untrusted JSON with only known fields (no prototype keys). */
export function sanitizeProjects(raw: unknown): Record<string, Project> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("projects must be an object");
  const out: Record<string, Project> = {};
  for (const [name, p] of Object.entries(raw as Record<string, unknown>)) {
    const proj = p as Record<string, unknown>;
    if (
      !proj ||
      typeof proj !== "object" ||
      typeof proj.createdAt !== "number" ||
      !Number.isFinite(proj.createdAt) ||
      !proj.vars ||
      typeof proj.vars !== "object" ||
      Array.isArray(proj.vars)
    ) {
      throw new Error(`malformed project ${JSON.stringify(name.slice(0, 64))}`);
    }
    const vars: Record<string, VarEntry> = {};
    for (const [key, entry] of Object.entries(proj.vars as Record<string, unknown>)) {
      if (!key || key === "__proto__") throw new Error("invalid var name");
      vars[key] = cleanEntry(entry);
    }
    out[name] = { createdAt: proj.createdAt, vars };
  }
  return out;
}

/** Low-level seal (tests and PR 3's push use sealForPeer). Does not check roles. */
export function sealProjects(
  sender: SyncIdentity,
  recipient: { id: string; x25519: string },
  projects: Record<string, Project>,
  opts: { now?: number; bundleId?: string } = {},
): SealedEnvelope {
  const names = checkProjectNames(Object.keys(projects));
  const payload: SealedPayload = { v: ENVELOPE_VERSION, projects: sanitizeProjects(projects) };
  const eph = crypto.generateKeyPairSync("x25519");
  const header: EnvelopeHeader = {
    v: ENVELOPE_VERSION,
    from: sender.id,
    to: recipient.id,
    bundleId: opts.bundleId ?? crypto.randomUUID(),
    createdAt: opts.now ?? Date.now(),
    projects: names,
    epk: rawPublicKey(eph.publicKey),
    nonce: crypto.randomBytes(NONCE_BYTES).toString("base64"),
  };
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: x25519PublicKey(recipient.x25519) });
  const key = deriveKey(shared, header, recipient.x25519);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, Buffer.from(header.nonce, "base64"));
  cipher.setAAD(headerBytes(header));
  const ct = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), "utf8")),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  key.fill(0);
  const sig = crypto.sign(null, sigMessage(header, ct), ed25519PrivateKey(sender));
  return { ...header, ct: ct.toString("base64"), sig: sig.toString("base64") };
}

/**
 * Seal the named projects of `vault` for a paired RECEIVER peer (by name or id).
 * Only projects cross — via extractScopedProjects; no other vault field.
 */
export function sealForPeer(
  vault: Vault,
  peerNameOrId: string,
  projectNames: string[],
  opts: { now?: number; bundleId?: string } = {},
): SealedEnvelope {
  const identity = vault.syncIdentity;
  if (!identity) throw new Error("this vault has no sync identity — pair first (abra sync pair)");
  const found = findPeer(vault, peerNameOrId);
  if (!found) throw new Error(`no paired peer named "${peerNameOrId}" — see: abra sync peers`);
  if (found.peer.role !== "receiver") {
    throw new Error(`peer "${found.peer.name}" is a source for this machine — only receivers can be pushed to`);
  }
  const names = validateScope(vault, projectNames);
  return sealProjects(identity, { id: found.id, x25519: found.peer.x25519 }, extractScopedProjects(vault, names), opts);
}

const ENVELOPE_KEYS = new Set(["v", "from", "to", "bundleId", "createdAt", "projects", "epk", "nonce", "ct", "sig"]);

/** Strict structural parse of an untrusted envelope (no crypto). */
export function parseEnvelope(raw: unknown): SealedEnvelope {
  const bad = (what: string): never => {
    throw new EnvelopeError("malformed", `malformed envelope: ${what}`);
  };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) bad("not an object");
  const e = raw as Record<string, unknown>;
  for (const k of Object.keys(e)) if (!ENVELOPE_KEYS.has(k)) bad(`unexpected field ${JSON.stringify(k.slice(0, 32))}`);
  if (e.v !== ENVELOPE_VERSION) bad("unsupported version");
  if (!isUuid(e.from) || !isUuid(e.to) || !isUuid(e.bundleId)) bad("ids must be UUIDs");
  if (typeof e.createdAt !== "number" || !Number.isSafeInteger(e.createdAt) || e.createdAt < 0) bad("createdAt");
  if (!Array.isArray(e.projects) || e.projects.some((p) => typeof p !== "string")) bad("projects");
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
    v: ENVELOPE_VERSION,
    from: e.from as string,
    to: e.to as string,
    bundleId: e.bundleId as string,
    createdAt: e.createdAt as number,
    projects: [...(e.projects as string[])],
    epk: e.epk as string,
    nonce: e.nonce as string,
    ct: e.ct as string,
    sig: e.sig as string,
  };
}

export interface VerifyOptions {
  now?: number;
  /** Receive-time freshness (±MAX_CLOCK_SKEW_MS). Off when applying an already-queued bundle. */
  checkFreshness?: boolean;
  maxSkewMs?: number;
  isReplay?: (bundleId: string) => boolean;
}

/**
 * Authenticate an envelope against pinned keys: recipient is me, sender is a
 * paired peer with role "source", Ed25519 signature over header+ct, project
 * names allowed, (optionally) fresh and not replayed. Throws EnvelopeError.
 */
export function verifyEnvelope(
  env: SealedEnvelope,
  trust: EnvelopeTrust,
  opts: VerifyOptions = {},
): { peerId: string; peerName: string } {
  if (env.to !== trust.myId) throw new EnvelopeError("wrong-recipient", "envelope is addressed to another identity");
  const peer = Object.prototype.hasOwnProperty.call(trust.peers, env.from) ? trust.peers[env.from] : undefined;
  if (!peer) throw new EnvelopeError("unknown-sender", "sender is not a paired peer");
  if (peer.role !== "source") {
    throw new EnvelopeError("sender-not-source", `peer "${peer.name}" is paired as a receiver, not a source`);
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      sigMessage(env, Buffer.from(env.ct, "base64")),
      ed25519PublicKey(peer.ed25519),
      Buffer.from(env.sig, "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new EnvelopeError("bad-signature", `signature does not match the pinned key of "${peer.name}"`);
  checkProjectNames(env.projects);
  if (opts.checkFreshness) {
    const now = opts.now ?? Date.now();
    const skew = opts.maxSkewMs ?? MAX_CLOCK_SKEW_MS;
    if (Math.abs(now - env.createdAt) > skew) {
      throw new EnvelopeError("stale", "envelope createdAt is outside the allowed clock window");
    }
  }
  if (opts.isReplay?.(env.bundleId)) throw new EnvelopeError("replay", "bundle was already received");
  return { peerId: env.from, peerName: peer.name };
}

/** Decrypt a verified envelope with this vault's X25519 key → projects (exactly the header's names). */
export function openEnvelope(env: SealedEnvelope, identity: SyncIdentity): Record<string, Project> {
  if (env.to !== identity.id) throw new EnvelopeError("wrong-recipient", "envelope is addressed to another identity");
  let payload: SealedPayload;
  try {
    const shared = crypto.diffieHellman({
      privateKey: x25519PrivateKey(identity),
      publicKey: x25519PublicKey(env.epk),
    });
    const key = deriveKey(shared, env, identity.x25519.publicKey);
    const raw = Buffer.from(env.ct, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(env.nonce, "base64"));
    decipher.setAAD(headerBytes(env));
    decipher.setAuthTag(raw.subarray(raw.length - GCM_TAG_BYTES));
    const plain = Buffer.concat([decipher.update(raw.subarray(0, raw.length - GCM_TAG_BYTES)), decipher.final()]);
    key.fill(0);
    payload = JSON.parse(plain.toString("utf8")) as SealedPayload;
  } catch {
    throw new EnvelopeError("decrypt-failed", "envelope could not be decrypted");
  }
  if (!payload || payload.v !== ENVELOPE_VERSION) throw new EnvelopeError("decrypt-failed", "unsupported payload");
  let projects: Record<string, Project>;
  try {
    projects = sanitizeProjects(payload.projects);
  } catch (err) {
    throw new EnvelopeError("bad-projects", err instanceof Error ? err.message : String(err));
  }
  const inner = Object.keys(projects).sort();
  const outer = [...env.projects].sort();
  if (inner.length !== outer.length || inner.some((n, i) => n !== outer[i])) {
    throw new EnvelopeError("bad-projects", "payload projects do not match the signed header");
  }
  return projects;
}
