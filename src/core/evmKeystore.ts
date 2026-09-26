import { createCipheriv, createDecipheriv, randomBytes, randomUUID, scryptSync } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";

/** Web3 Secret Storage Definition (scrypt + aes-128-ctr). Address omitted — cast does not need it. */
export interface EvmKeystoreV3 {
  version: 3;
  id: string;
  crypto: {
    cipher: "aes-128-ctr";
    cipherparams: { iv: string };
    ciphertext: string;
    kdf: "scrypt";
    kdfparams: {
      dklen: number;
      n: number;
      p: number;
      r: number;
      salt: string;
    };
    mac: string;
  };
}

const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 256 * 1024 * 1024 } as const;

function normalizePrivateKeyBytes(privateKey: string): Buffer {
  const hex = privateKey.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("Invalid private key (expected 32-byte hex)");
  }
  return Buffer.from(hex, "hex");
}

function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(Buffer.from(password, "utf8"), salt, 32, SCRYPT_OPTS);
}

function macHex(derivedKey: Buffer, ciphertext: Buffer): string {
  const data = Buffer.concat([derivedKey.subarray(16, 32), ciphertext]);
  return Buffer.from(keccak_256(data)).toString("hex");
}

/**
 * Build a throwaway Web3 Secret Storage v3 keystore for Foundry `cast`
 * (`ETH_KEYSTORE` / `ETH_PASSWORD`). Address field intentionally omitted.
 */
export function buildEvmKeystoreV3(privateKey: string, password: string): EvmKeystoreV3 {
  const keyBytes = normalizePrivateKeyBytes(privateKey);
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derived = deriveKey(password, salt);
  const cipher = createCipheriv("aes-128-ctr", derived.subarray(0, 16), iv);
  const ciphertext = Buffer.concat([cipher.update(keyBytes), cipher.final()]);
  return {
    version: 3,
    id: randomUUID(),
    crypto: {
      cipher: "aes-128-ctr",
      cipherparams: { iv: iv.toString("hex") },
      ciphertext: ciphertext.toString("hex"),
      kdf: "scrypt",
      kdfparams: {
        dklen: 32,
        n: SCRYPT_OPTS.N,
        r: SCRYPT_OPTS.r,
        p: SCRYPT_OPTS.p,
        salt: salt.toString("hex"),
      },
      mac: macHex(derived, ciphertext),
    },
  };
}

/** Decrypt a v3 keystore produced by {@link buildEvmKeystoreV3} (known-answer / round-trip tests). */
export function decryptEvmKeystoreV3(keystore: EvmKeystoreV3, password: string): string {
  const { crypto: c } = keystore;
  if (c.kdf !== "scrypt" || c.cipher !== "aes-128-ctr") {
    throw new Error("Unsupported keystore cipher/kdf");
  }
  const salt = Buffer.from(c.kdfparams.salt, "hex");
  const iv = Buffer.from(c.cipherparams.iv, "hex");
  const ciphertext = Buffer.from(c.ciphertext, "hex");
  const derived = deriveKey(password, salt);
  const expectedMac = macHex(derived, ciphertext);
  if (expectedMac !== c.mac.toLowerCase() && expectedMac !== c.mac) {
    if (expectedMac.toLowerCase() !== c.mac.toLowerCase()) {
      throw new Error("Keystore MAC mismatch (wrong password or corrupt file)");
    }
  }
  const decipher = createDecipheriv("aes-128-ctr", derived.subarray(0, 16), iv);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString("hex");
}

/** Redact private key (with/without 0x), password, and paths from cast/error text. */
export function scrubCastSecrets(
  text: string,
  secrets: {
    privateKey?: string;
    password?: string;
    paths?: string[];
  },
): string {
  let out = text;
  for (const p of secrets.paths ?? []) {
    if (!p) continue;
    out = out.split(p).join("[redacted-path]");
  }
  if (secrets.password) {
    out = out.split(secrets.password).join("[redacted-password]");
  }
  const pk = secrets.privateKey?.trim();
  if (pk) {
    const bare = pk.replace(/^0x/i, "");
    const variants = new Set([pk, bare, `0x${bare}`, `0X${bare}`]);
    for (const v of variants) {
      if (!v) continue;
      // case-insensitive replace for hex material
      const re = new RegExp(v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      out = out.replace(re, "[redacted-key]");
    }
  }
  return out;
}
