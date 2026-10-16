import fs from "node:fs";
import path from "node:path";
import { abraDir } from "../core/paths.js";
import {
  assertValidPublicKeys,
  identityFingerprint,
  isUuid,
} from "../sync/identity.js";
import {
  ensureRemoteDir,
  readPrivateFile,
  remoteDir,
  writePrivateFile,
} from "./private-fs.js";

/**
 * Pinned hub (source) public keys, stored OUTSIDE the vault so a locked
 * receiver can verify hub signatures during remote unlock.
 *
 * File: `<abraDir>/remote/hub-pin.json` (0600).
 */

export const HUB_PIN_FILENAME = "hub-pin.json";

export interface HubPin {
  v: 1;
  /** Hub sync / device identity id (UUID). */
  deviceId: string;
  /** base64 raw 32-byte public keys */
  ed25519: string;
  x25519: string;
  pinnedAt: number;
}

export class HubPinConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HubPinConflictError";
  }
}

export function hubPinFile(base: string = abraDir()): string {
  return path.join(remoteDir(base), HUB_PIN_FILENAME);
}

function corruptError(): Error {
  return new Error("remote hub pin is malformed — refusing to use or replace it automatically");
}

function isValidHubPin(raw: unknown): raw is HubPin {
  if (!raw || typeof raw !== "object") return false;
  const p = raw as HubPin;
  if (p.v !== 1 || !isUuid(p.deviceId) || typeof p.pinnedAt !== "number") return false;
  if (typeof p.ed25519 !== "string" || typeof p.x25519 !== "string") return false;
  try {
    assertValidPublicKeys(p.ed25519, p.x25519);
    return true;
  } catch {
    return false;
  }
}

function parseHubPin(text: string): HubPin {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw corruptError();
  }
  if (!isValidHubPin(parsed)) throw corruptError();
  return parsed;
}

/** Null when no pin is stored. Fail closed on bad perms or corrupt JSON. */
export function getHubPin(base: string = abraDir()): HubPin | null {
  const file = hubPinFile(base);
  if (!fs.existsSync(file)) return null;
  return parseHubPin(readPrivateFile(file, base));
}

export interface SetHubPinInput {
  deviceId: string;
  ed25519: string;
  x25519: string;
  pinnedAt?: number;
}

/**
 * Pin the hub's public keys. Refuses to silently replace a different pinned
 * identity unless `force` is set (impersonation refusal, like sync peers).
 */
export function setHubPin(
  input: SetHubPinInput,
  opts: { force?: boolean; base?: string } = {},
): HubPin {
  const base = opts.base ?? abraDir();
  assertValidPublicKeys(input.ed25519, input.x25519);
  if (!isUuid(input.deviceId)) {
    throw new Error("hub pin deviceId must be a UUID");
  }

  const next: HubPin = {
    v: 1,
    deviceId: input.deviceId,
    ed25519: input.ed25519,
    x25519: input.x25519,
    pinnedAt: input.pinnedAt ?? Date.now(),
  };

  const existing = getHubPin(base);
  if (existing) {
    const same =
      existing.deviceId === next.deviceId &&
      existing.ed25519 === next.ed25519 &&
      existing.x25519 === next.x25519;
    if (same) {
      // Idempotent: keep original pinnedAt.
      return existing;
    }
    if (!opts.force) {
      const storedFp = identityFingerprint(existing.ed25519, existing.x25519);
      const presentedFp = identityFingerprint(next.ed25519, next.x25519);
      throw new HubPinConflictError(
        `hub is already pinned with different keys ` +
          `(stored ${storedFp}, presented ${presentedFp}) — possible impersonation. ` +
          `If the hub was really reset, pass force to replace the pin`,
      );
    }
  }

  ensureRemoteDir(base);
  writePrivateFile(hubPinFile(base), `${JSON.stringify(next, null, 2)}\n`);
  const loaded = getHubPin(base);
  if (!loaded) throw new Error("failed to persist hub pin");
  return loaded;
}

export function clearHubPin(base: string = abraDir()): void {
  fs.rmSync(hubPinFile(base), { force: true });
}
