import crypto from "node:crypto";
import type { SyncIdentity, SyncPeerRole } from "../core/vault.js";
import { ed25519PrivateKey, ed25519PublicKey, lengthPrefixed } from "./identity.js";
import { SAS_WORDS } from "./wordlist.js";

export const PAIR_PROTOCOL = "abra-sync-pair-v1";
export const SAS_DOMAIN = "abra-sync-sas-v1";
const SIG_DOMAIN = "abra-sync-pair-sig-v1";

export type PairSide = "listener" | "connector";

/** One side's public pairing message (no private material, no vault content). */
export interface PairHello {
  protocol: typeof PAIR_PROTOCOL;
  id: string;
  name: string;
  ed25519: string;
  x25519: string;
  /** base64 of 32 random bytes */
  nonce: string;
  /** Sender's own role; a connector may send null to accept the opposite of the listener. */
  role: SyncPeerRole | null;
}

export interface TranscriptInput {
  /** TLS cert fingerprint of the listener (any `AA:BB…` / hex formatting). */
  tlsFingerprint: string;
  listener: PairHello & { role: SyncPeerRole };
  connector: PairHello & { role: SyncPeerRole };
}

function normalizeFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
}

function helloParts(side: PairSide, h: PairHello & { role: SyncPeerRole }): Buffer[] {
  return [side, h.protocol, h.id, h.name, h.ed25519, h.x25519, h.nonce, h.role].map((s) =>
    Buffer.from(s, "utf8"),
  );
}

/** SHA-256 binding protocol, TLS cert, both public key sets, nonces, names and resolved roles. */
export function transcriptHash(input: TranscriptInput): Buffer {
  return crypto
    .createHash("sha256")
    .update(
      lengthPrefixed([
        Buffer.from(PAIR_PROTOCOL, "utf8"),
        Buffer.from(normalizeFingerprint(input.tlsFingerprint), "utf8"),
        ...helloParts("listener", input.listener),
        ...helloParts("connector", input.connector),
      ]),
    )
    .digest();
}

function sigMessage(side: PairSide, transcript: Buffer): Buffer {
  return lengthPrefixed([Buffer.from(SIG_DOMAIN, "utf8"), Buffer.from(side, "utf8"), transcript]);
}

/** Ed25519 signature (base64) proving possession of `identity`'s key for this transcript. */
export function signTranscript(identity: SyncIdentity, side: PairSide, transcript: Buffer): string {
  return crypto.sign(null, sigMessage(side, transcript), ed25519PrivateKey(identity)).toString("base64");
}

export function verifyTranscript(
  ed25519Pub: string,
  side: PairSide,
  transcript: Buffer,
  signatureB64: string,
): boolean {
  try {
    const sig = Buffer.from(signatureB64, "base64");
    if (sig.length !== 64) return false;
    return crypto.verify(null, sigMessage(side, transcript), ed25519PublicKey(ed25519Pub), sig);
  } catch {
    return false;
  }
}

export interface SafetyCode {
  /** 6 words, one per byte (48 bits). */
  words: string[];
  /** The same 48 bits as 12 decimal digits (value mod 10^12), "123 456 789 012". */
  digits: string;
}

export function safetyCode(transcript: Buffer): SafetyCode {
  const h = crypto
    .createHash("sha256")
    .update(lengthPrefixed([Buffer.from(SAS_DOMAIN, "utf8"), transcript]))
    .digest();
  const bytes = h.subarray(0, 6);
  const words = [...bytes].map((b) => SAS_WORDS[b]);
  const n = BigInt(`0x${bytes.toString("hex")}`) % 10n ** 12n;
  const digits = (n.toString().padStart(12, "0").match(/.{3}/g) ?? []).join(" ");
  return { words, digits };
}
