import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  assertBlobMatchesMasterKey,
  clearUnlockBlob,
  createAndWriteUnlockBlob,
  generateWrapKey,
  masterKeyFingerprint,
  readUnlockBlob,
  ReEnrollNeededError,
  unlockBlobFile,
  unwrapMasterKey,
  wrapMasterKey,
} from "./unlock-blob.js";
import { remoteDir } from "./private-fs.js";

const posix = process.platform !== "win32";
const FP_RE = /^[0-9a-f]{4}( [0-9a-f]{4}){7}$/;
const DEVICE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-blob-"));
}

describe("unlock blob", () => {
  let base: string;
  let masterKey: Buffer;
  let wrapKey: Buffer;

  beforeEach(() => {
    base = tmpBase();
    masterKey = crypto.randomBytes(32);
    wrapKey = generateWrapKey();
  });

  afterEach(() => {
    masterKey.fill(0);
    wrapKey.fill(0);
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("round-trips wrap → unwrap and writes 0600 blob", () => {
    const blob = createAndWriteUnlockBlob(masterKey, wrapKey, DEVICE_ID, { base });
    expect(blob.masterKeyFingerprint).toMatch(FP_RE);
    expect(blob.masterKeyFingerprint).toBe(masterKeyFingerprint(masterKey));

    const loaded = readUnlockBlob(base);
    expect(loaded).toEqual(blob);

    const opened = unwrapMasterKey(blob, wrapKey);
    expect(opened.equals(masterKey)).toBe(true);
    opened.fill(0);

    if (posix) {
      expect(fs.statSync(unlockBlobFile(base)).mode & 0o777).toBe(0o600);
      expect(fs.statSync(remoteDir(base)).mode & 0o777).toBe(0o700);
    }
  });

  it("wrong W fails to decrypt", () => {
    const blob = wrapMasterKey(masterKey, wrapKey, DEVICE_ID);
    const wrong = crypto.randomBytes(32);
    expect(() => unwrapMasterKey(blob, wrong)).toThrow(/could not be decrypted/);
    wrong.fill(0);
  });

  it("fingerprint mismatch → re-enroll needed", () => {
    const blob = wrapMasterKey(masterKey, wrapKey, DEVICE_ID);
    const otherKey = crypto.randomBytes(32);
    expect(() => assertBlobMatchesMasterKey(blob, otherKey)).toThrow(ReEnrollNeededError);
    expect(() => unwrapMasterKey(blob, wrapKey, { expectedMasterKey: otherKey })).toThrow(
      ReEnrollNeededError,
    );
    expect(() => unwrapMasterKey(blob, wrapKey, { expectedMasterKey: otherKey })).toThrow(
      /re-enroll needed/i,
    );
    // Correct key still unwraps when fingerprint matches.
    const ok = unwrapMasterKey(blob, wrapKey, { expectedMasterKey: masterKey });
    expect(ok.equals(masterKey)).toBe(true);
    ok.fill(0);
    otherKey.fill(0);
  });

  it("AAD binds deviceId — tampering deviceId breaks decrypt", () => {
    const blob = wrapMasterKey(masterKey, wrapKey, DEVICE_ID);
    const tampered = {
      ...blob,
      deviceId: "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee",
    };
    expect(() => unwrapMasterKey(tampered, wrapKey)).toThrow(/could not be decrypted/);
  });

  it("clear removes the file; fingerprint never embeds the raw key", () => {
    createAndWriteUnlockBlob(masterKey, wrapKey, DEVICE_ID, { base });
    const text = fs.readFileSync(unlockBlobFile(base), "utf8");
    expect(text).not.toContain(masterKey.toString("base64"));
    expect(text).not.toContain(wrapKey.toString("base64"));
    clearUnlockBlob(base);
    expect(readUnlockBlob(base)).toBeNull();
  });

  it("masterKeyFingerprint is deterministic and key-sensitive", () => {
    const a = masterKeyFingerprint(masterKey);
    const b = masterKeyFingerprint(Buffer.from(masterKey));
    expect(a).toBe(b);
    const other = crypto.randomBytes(32);
    expect(masterKeyFingerprint(other)).not.toBe(a);
    other.fill(0);
  });
});
