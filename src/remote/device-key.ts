import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";
import {
  assertValidPublicKeys,
  decodeRawKey,
  generateSyncIdentity,
  isUuid,
  lengthPrefixed,
} from "../sync/identity.js";
import {
  ensureRemoteDir,
  readPrivateFile,
  remoteDir,
  writePrivateFile,
} from "./private-fs.js";

/**
 * Per-device Ed25519 + X25519 key pair stored OUTSIDE the vault so a locked
 * receiver can still authenticate remote-unlock challenges. Alone, this key
 * can only ASK the hub — it cannot unwrap the vault.
 *
 * File: `<abraDir>/remote/device-key.json` (0600 inside a 0700 dir).
 */

export const DEVICE_KEY_FILENAME = "device-key.json";
export const DEVICE_FINGERPRINT_DOMAIN = "abra-remote-device-v1";

export interface DeviceKey {
  v: 1;
  id: string;
  createdAt: number;
  ed25519: { publicKey: string; privateKey: string };
  x25519: { publicKey: string; privateKey: string };
}

export interface PublicDeviceKey {
  id: string;
  ed25519: string;
  x25519: string;
  fingerprint: string;
}

export function deviceKeyFile(base: string = abraDir()): string {
  return path.join(remoteDir(base), DEVICE_KEY_FILENAME);
}

/**
 * SHA-256 over ("abra-remote-device-v1", ed25519, x25519), length-prefixed —
 * same rendering as sync identity fingerprints (8 groups of 4 hex).
 */
export function deviceKeyFingerprint(ed25519Pub: string, x25519Pub: string): string {
  const digest = crypto
    .createHash("sha256")
    .update(
      lengthPrefixed([
        Buffer.from(DEVICE_FINGERPRINT_DOMAIN, "utf8"),
        decodeRawKey(ed25519Pub),
        decodeRawKey(x25519Pub),
      ]),
    )
    .digest("hex")
    .slice(0, 32);
  return (digest.match(/.{4}/g) ?? []).join(" ");
}

export function publicDeviceKey(key: DeviceKey): PublicDeviceKey {
  return {
    id: key.id,
    ed25519: key.ed25519.publicKey,
    x25519: key.x25519.publicKey,
    fingerprint: deviceKeyFingerprint(key.ed25519.publicKey, key.x25519.publicKey),
  };
}

function isValidDeviceKey(raw: unknown): raw is DeviceKey {
  if (!raw || typeof raw !== "object") return false;
  const k = raw as DeviceKey;
  if (k.v !== 1 || !isUuid(k.id) || typeof k.createdAt !== "number") return false;
  if (!k.ed25519 || !k.x25519) return false;
  try {
    assertValidPublicKeys(k.ed25519.publicKey, k.x25519.publicKey);
    decodeRawKey(k.ed25519.privateKey);
    decodeRawKey(k.x25519.privateKey);
    return true;
  } catch {
    return false;
  }
}

/** Errors never include file contents or private key material. */
function corruptError(): Error {
  return new Error("remote device key is malformed — refusing to use or replace it automatically");
}

function parseDeviceKey(text: string): DeviceKey {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw corruptError();
  }
  if (!isValidDeviceKey(parsed)) throw corruptError();
  return parsed;
}

/**
 * Load the on-disk device key. Fail closed on bad perms (POSIX) or corrupt JSON.
 * Does not create a key. Throws if missing.
 */
export function loadDeviceKey(base: string = abraDir()): DeviceKey {
  const file = deviceKeyFile(base);
  if (!fs.existsSync(file)) {
    throw new Error("remote device key not found — run: abra remote whoami");
  }
  return parseDeviceKey(readPrivateFile(file, base));
}

function mintDeviceKey(now: number): DeviceKey {
  // Same key shape as sync identity; separate file + fingerprint domain.
  const id = generateSyncIdentity(now);
  return {
    v: 1,
    id: id.id,
    createdAt: id.createdAt,
    ed25519: id.ed25519,
    x25519: id.x25519,
  };
}

/**
 * Return the existing device key, or create one atomically (0600).
 * A present-but-corrupt file throws rather than being silently replaced.
 */
export function getOrCreateDeviceKey(
  opts: { base?: string; now?: number } = {},
): { key: DeviceKey; created: boolean; public: PublicDeviceKey } {
  const base = opts.base ?? abraDir();
  const file = deviceKeyFile(base);
  ensureRemoteDir(base);

  if (fs.existsSync(file)) {
    const key = loadDeviceKey(base);
    return { key, created: false, public: publicDeviceKey(key) };
  }

  const key = mintDeviceKey(opts.now ?? Date.now());
  writePrivateFile(file, `${JSON.stringify(key, null, 2)}\n`);
  // Re-load through the fail-closed path so perms are checked after write.
  const loaded = loadDeviceKey(base);
  return { key: loaded, created: true, public: publicDeviceKey(loaded) };
}

/** Convenience: public-only view (creates the key if missing). */
export function getOrCreatePublicDeviceKey(
  opts: { base?: string; now?: number } = {},
): PublicDeviceKey & { created: boolean } {
  const { public: pub, created } = getOrCreateDeviceKey(opts);
  return { ...pub, created };
}
