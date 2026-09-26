import crypto from "node:crypto";
import os from "node:os";
import type { PlatformKeystore } from "./types.js";
import { KeystoreError } from "./types.js";
import { loadKeytar } from "./keytar-loader.js";
import { resolveMasterKey } from "../core/masterKey.js";

export const KEYTAR_SERVICE = "abracadabra-master-key";
const ACCOUNT = os.userInfo().username;

const LOCKED_RE = /locked|dismiss|cancel|cancelled|canceled|user.?interaction|secret.?service.?is.?locked/i;

function classifyKeytarThrow(e: unknown): KeystoreError {
  const msg = e instanceof Error ? e.message : String(e);
  if (LOCKED_RE.test(msg)) {
    return new KeystoreError(
      "locked",
      `Credential store is locked or cancelled: ${msg}`,
      "Unlock your system keyring, or set ABRA_KEYSTORE=passphrase-file",
    );
  }
  return new KeystoreError("unavailable", `Credential store unavailable: ${msg}`);
}

export class KeytarKeystore implements PlatformKeystore {
  readonly id = "keytar";

  async getMasterKey(): Promise<Buffer> {
    let existing: string | null;
    try {
      const keytar = await loadKeytar();
      existing = await keytar.getPassword(KEYTAR_SERVICE, ACCOUNT);
    } catch (e) {
      throw classifyKeytarThrow(e);
    }
    if (existing == null) {
      throw new KeystoreError("not_found", "Master key not found in credential store");
    }
    const key = Buffer.from(existing, "base64");
    if (key.length !== 32) {
      throw new KeystoreError("mismatch", "Corrupt master key in credential store");
    }
    return key;
  }

  async createMasterKey(): Promise<Buffer> {
    let existing: string | null;
    try {
      const keytar = await loadKeytar();
      existing = await keytar.getPassword(KEYTAR_SERVICE, ACCOUNT);
    } catch (e) {
      throw classifyKeytarThrow(e);
    }
    if (existing != null) {
      throw new Error(
        "Master key already exists in credential store; refusing to overwrite",
      );
    }
    const key = crypto.randomBytes(32);
    await this.storeMasterKey(key);
    return key;
  }

  async getOrCreateMasterKey(): Promise<Buffer> {
    // Never mint when vault.enc exists — resolveMasterKey gates on not_found + no vault.
    return resolveMasterKey(this);
  }

  async storeMasterKey(key: Buffer): Promise<void> {
    if (key.length !== 32) throw new Error("Master key must be 32 bytes");
    const keytar = await loadKeytar();
    await keytar.setPassword(KEYTAR_SERVICE, ACCOUNT, key.toString("base64"));
    const readback = await keytar.getPassword(KEYTAR_SERVICE, ACCOUNT);
    if (!readback || readback !== key.toString("base64")) {
      throw new Error("Failed to verify master key in credential store");
    }
  }
}

export async function probeKeytar(): Promise<{ ok: boolean; detail?: string }> {
  try {
    const keytar = await loadKeytar();
    const probe = `probe-${Date.now()}`;
    await keytar.setPassword(KEYTAR_SERVICE, `${ACCOUNT}-probe`, probe);
    const got = await keytar.getPassword(KEYTAR_SERVICE, `${ACCOUNT}-probe`);
    await keytar.deletePassword(KEYTAR_SERVICE, `${ACCOUNT}-probe`);
    if (got !== probe) return { ok: false, detail: "readback mismatch" };
    return { ok: true };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : String(err) };
  }
}
