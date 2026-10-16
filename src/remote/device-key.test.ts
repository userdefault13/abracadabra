import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  deviceKeyFile,
  deviceKeyFingerprint,
  getOrCreateDeviceKey,
  loadDeviceKey,
  publicDeviceKey,
} from "./device-key.js";
import { assertPrivatePath, remoteDir } from "./private-fs.js";
import { isRemoteUnlockEnabled } from "./feature.js";
import { generateSyncIdentity, identityFingerprint } from "../sync/identity.js";

const posix = process.platform !== "win32";
const FP_RE = /^[0-9a-f]{4}( [0-9a-f]{4}){7}$/;

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-remote-"));
}

describe("isRemoteUnlockEnabled", () => {
  const prev = process.env.ABRA_REMOTE_UNLOCK;
  afterEach(() => {
    if (prev === undefined) delete process.env.ABRA_REMOTE_UNLOCK;
    else process.env.ABRA_REMOTE_UNLOCK = prev;
  });

  it("is off by default", () => {
    delete process.env.ABRA_REMOTE_UNLOCK;
    expect(isRemoteUnlockEnabled()).toBe(false);
  });

  it("is on only when ABRA_REMOTE_UNLOCK=1", () => {
    process.env.ABRA_REMOTE_UNLOCK = "1";
    expect(isRemoteUnlockEnabled()).toBe(true);
    process.env.ABRA_REMOTE_UNLOCK = "true";
    expect(isRemoteUnlockEnabled()).toBe(false);
  });
});

describe("device key", () => {
  let base: string;

  beforeEach(() => {
    base = tmpBase();
  });

  afterEach(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("round-trips create → load with 0600 file in 0700 dir", () => {
    const first = getOrCreateDeviceKey({ base, now: 42 });
    expect(first.created).toBe(true);
    expect(first.public.fingerprint).toMatch(FP_RE);
    expect(first.key.createdAt).toBe(42);

    const again = getOrCreateDeviceKey({ base });
    expect(again.created).toBe(false);
    expect(again.key).toEqual(first.key);
    expect(again.public.fingerprint).toBe(first.public.fingerprint);

    const loaded = loadDeviceKey(base);
    expect(publicDeviceKey(loaded)).toEqual(first.public);

    if (posix) {
      expect(fs.statSync(deviceKeyFile(base)).mode & 0o777).toBe(0o600);
      expect(fs.statSync(remoteDir(base)).mode & 0o777).toBe(0o700);
    }
  });

  it("fingerprint is domain-separated from sync identity fingerprint", () => {
    const { key } = getOrCreateDeviceKey({ base });
    const deviceFp = deviceKeyFingerprint(key.ed25519.publicKey, key.x25519.publicKey);
    const syncFp = identityFingerprint(key.ed25519.publicKey, key.x25519.publicKey);
    expect(deviceFp).not.toBe(syncFp);
  });

  it("fails closed on group/world-readable file (POSIX)", function () {
    if (!posix) return; // POSIX-only (no file modes on win32)
    const { key } = getOrCreateDeviceKey({ base });
    fs.chmodSync(deviceKeyFile(base), 0o644);
    expect(() => loadDeviceKey(base)).toThrow(/group\/world-readable/);
    // error must not leak private key material
    try {
      loadDeviceKey(base);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      expect(msg).not.toContain(key.ed25519.privateKey);
      expect(msg).not.toContain(key.x25519.privateKey);
    }
  });

  it("fails closed on group/world-readable dir (POSIX)", function () {
    if (!posix) return; // POSIX-only (no file modes on win32)
    getOrCreateDeviceKey({ base });
    fs.chmodSync(remoteDir(base), 0o755);
    expect(() => loadDeviceKey(base)).toThrow(/group\/world-readable/);
  });

  it("fails closed on owner uid mismatch (POSIX)", function () {
    if (!posix || typeof process.getuid !== "function") return; // POSIX-only (no file modes on win32)
    getOrCreateDeviceKey({ base });
    expect(() =>
      assertPrivatePath(deviceKeyFile(base), { expectDir: false, uid: process.getuid!() + 1 }),
    ).toThrow(/owner mismatch/);
  });

  it("refuses corrupt files without echoing contents or private keys", () => {
    fs.mkdirSync(remoteDir(base), { recursive: true, mode: 0o700 });
    const planted = generateSyncIdentity();
    const poison = JSON.stringify({
      v: 1,
      id: "not-a-uuid",
      createdAt: 1,
      ed25519: planted.ed25519,
      x25519: planted.x25519,
      secretLeak: planted.ed25519.privateKey,
    });
    fs.writeFileSync(deviceKeyFile(base), poison, { mode: 0o600 });

    expect(() => loadDeviceKey(base)).toThrow(/malformed/);
    try {
      loadDeviceKey(base);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      expect(msg).not.toContain(planted.ed25519.privateKey);
      expect(msg).not.toContain(planted.x25519.privateKey);
      expect(msg).not.toContain("secretLeak");
      expect(msg).not.toContain(poison);
    }

    // Corrupt must not be silently replaced
    expect(() => getOrCreateDeviceKey({ base })).toThrow(/malformed/);
  });

  it("refuses invalid JSON without echoing the file body", () => {
    fs.mkdirSync(remoteDir(base), { recursive: true, mode: 0o700 });
    const body = `{"v":1,"leak":"${generateSyncIdentity().ed25519.privateKey}"}`;
    fs.writeFileSync(deviceKeyFile(base), `not-json ${body}`, { mode: 0o600 });
    try {
      loadDeviceKey(base);
      expect.fail("expected throw");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      expect(msg).toMatch(/malformed/);
      expect(msg).not.toContain("leak");
      expect(msg).not.toContain(body);
    }
  });

  it("publicDeviceKey never carries private keys", () => {
    const { key, public: pub } = getOrCreateDeviceKey({ base });
    const text = JSON.stringify(pub);
    expect(text).not.toContain(key.ed25519.privateKey);
    expect(text).not.toContain(key.x25519.privateKey);
    expect(text).not.toMatch(/privateKey/);
  });
});
