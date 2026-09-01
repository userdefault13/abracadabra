import crypto from "node:crypto";
import os from "node:os";
import type { PlatformKeystore } from "./types.js";
import { loadKeytar } from "./keytar-loader.js";

export const KEYTAR_SERVICE = "abracadabra-master-key";
const ACCOUNT = os.userInfo().username;

export class KeytarKeystore implements PlatformKeystore {
  readonly id = "keytar";

  async getOrCreateMasterKey(): Promise<Buffer> {
    const keytar = await loadKeytar();
    const existing = await keytar.getPassword(KEYTAR_SERVICE, ACCOUNT);
    if (existing) {
      const key = Buffer.from(existing, "base64");
      if (key.length !== 32) throw new Error("Corrupt master key in credential store");
      return key;
    }
    const key = crypto.randomBytes(32);
    await this.storeMasterKey(key);
    return key;
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
