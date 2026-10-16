import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateSyncIdentity } from "../sync/identity.js";
import {
  clearHubPin,
  getHubPin,
  HubPinConflictError,
  hubPinFile,
  setHubPin,
} from "./hub-pin.js";
import { remoteDir } from "./private-fs.js";

const posix = process.platform !== "win32";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-hubpin-"));
}

function fakeHub() {
  const id = generateSyncIdentity();
  return {
    deviceId: id.id,
    ed25519: id.ed25519.publicKey,
    x25519: id.x25519.publicKey,
  };
}

describe("hub pin", () => {
  let base: string;

  beforeEach(() => {
    base = tmpBase();
  });

  afterEach(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("set → get round-trip; clear removes", () => {
    expect(getHubPin(base)).toBeNull();
    const hub = fakeHub();
    const pinned = setHubPin({ ...hub, pinnedAt: 99 }, { base });
    expect(pinned.deviceId).toBe(hub.deviceId);
    expect(pinned.pinnedAt).toBe(99);
    expect(getHubPin(base)).toEqual(pinned);

    // Idempotent same keys
    const again = setHubPin(hub, { base });
    expect(again.pinnedAt).toBe(99);

    if (posix) {
      expect(fs.statSync(hubPinFile(base)).mode & 0o777).toBe(0o600);
      expect(fs.statSync(remoteDir(base)).mode & 0o777).toBe(0o700);
    }

    clearHubPin(base);
    expect(getHubPin(base)).toBeNull();
  });

  it("refuses to silently replace a different pinned key", () => {
    const a = fakeHub();
    const b = fakeHub();
    setHubPin(a, { base });
    expect(() => setHubPin(b, { base })).toThrow(HubPinConflictError);
    expect(() => setHubPin(b, { base })).toThrow(/impersonation/);
    expect(getHubPin(base)?.deviceId).toBe(a.deviceId);

    const replaced = setHubPin(b, { base, force: true });
    expect(replaced.deviceId).toBe(b.deviceId);
    expect(getHubPin(base)?.ed25519).toBe(b.ed25519);
  });

  it("conflict errors never include private key material", () => {
    const fullA = generateSyncIdentity();
    const fullB = generateSyncIdentity();
    setHubPin(
      { deviceId: fullA.id, ed25519: fullA.ed25519.publicKey, x25519: fullA.x25519.publicKey },
      { base },
    );
    try {
      setHubPin(
        { deviceId: fullB.id, ed25519: fullB.ed25519.publicKey, x25519: fullB.x25519.publicKey },
        { base },
      );
      expect.fail("expected conflict");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      expect(msg).not.toContain(fullA.ed25519.privateKey);
      expect(msg).not.toContain(fullA.x25519.privateKey);
      expect(msg).not.toContain(fullB.ed25519.privateKey);
      expect(msg).not.toContain(fullB.x25519.privateKey);
    }
  });

  it("refuses corrupt pin without echoing contents", () => {
    fs.mkdirSync(remoteDir(base), { recursive: true, mode: 0o700 });
    const leak = generateSyncIdentity().ed25519.privateKey;
    const body = JSON.stringify({ v: 1, deviceId: "bad", ed25519: "x", x25519: "y", leak });
    fs.writeFileSync(hubPinFile(base), body, { mode: 0o600 });
    try {
      getHubPin(base);
      expect.fail("expected throw");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      expect(msg).toMatch(/malformed/);
      expect(msg).not.toContain(leak);
      expect(msg).not.toContain(body);
    }
  });

  it("fails closed on world-readable pin file (POSIX)", function () {
    if (!posix) this.skip();
    setHubPin(fakeHub(), { base });
    fs.chmodSync(hubPinFile(base), 0o644);
    expect(() => getHubPin(base)).toThrow(/group\/world-readable/);
  });
});
