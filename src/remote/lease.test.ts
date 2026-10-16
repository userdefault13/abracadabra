import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getOrCreateDeviceKey } from "./device-key.js";
import { setHubPin } from "./hub-pin.js";
import {
  LEASE_DEFAULT_TTL_SECONDS,
  LEASE_PATH,
  LeaseError,
  openSealedLease,
  parseSealedLease,
  sealLease,
  verifySealedLease,
} from "./lease.js";
import { UnlockSession } from "./listener.js";
import { LeaseStore } from "../agent/lease-store.js";
import { generateSyncIdentity } from "../sync/identity.js";

const SECRET = "lease-roundtrip-secret-xyz";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-lease-crypto-"));
}

describe("lease crypto", () => {
  let base: string;
  const envBackup = { ...process.env };

  beforeEach(() => {
    base = tmpBase();
    process.env.ABRA_REMOTE_UNLOCK = "1";
    process.env.ABRA_DIR = base;
  });

  afterEach(() => {
    process.env = { ...envBackup };
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("seal → verify → open round-trip", () => {
    const hub = generateSyncIdentity();
    const { key: device } = getOrCreateDeviceKey({ base });
    setHubPin(
      { deviceId: hub.id, ed25519: hub.ed25519.publicKey, x25519: hub.x25519.publicKey },
      { base },
    );
    const lease = sealLease({
      hub,
      peer: { id: device.id, x25519: device.x25519.publicKey },
      project: "demo",
      binding: { exe: "/bin/demo", dev: 1, ino: 2 },
      vars: { K: { value: SECRET, secret: true, updatedAt: 1 } },
      ttlSeconds: LEASE_DEFAULT_TTL_SECONDS,
      issuedAt: Date.now(),
    });
    const pin = setHubPin(
      { deviceId: hub.id, ed25519: hub.ed25519.publicKey, x25519: hub.x25519.publicKey },
      { base },
    );
    verifySealedLease(lease, pin, { expectedPeerId: device.id });
    const opened = openSealedLease(lease, device);
    expect(opened.vars.K.value).toBe(SECRET);
    expect(JSON.stringify(lease)).not.toContain(SECRET);
  });

  it("default ttl is 7 days", () => {
    const hub = generateSyncIdentity();
    const { key: device } = getOrCreateDeviceKey({ base });
    const issuedAt = 1_700_000_000_000;
    const lease = sealLease({
      hub,
      peer: { id: device.id, x25519: device.x25519.publicKey },
      project: "demo",
      binding: { exe: "/bin/demo", dev: 1, ino: 2 },
      vars: { K: { value: "x", secret: true, updatedAt: 1 } },
      issuedAt,
    });
    expect(lease.expiresAt - lease.issuedAt).toBe(LEASE_DEFAULT_TTL_SECONDS * 1000);
  });

  it("parse rejects unexpected fields without leaking ct", () => {
    const hub = generateSyncIdentity();
    const { key: device } = getOrCreateDeviceKey({ base });
    const lease = sealLease({
      hub,
      peer: { id: device.id, x25519: device.x25519.publicKey },
      project: "demo",
      binding: { exe: "/bin/demo", dev: 1, ino: 2 },
      vars: { K: { value: SECRET, secret: true, updatedAt: 1 } },
    });
    try {
      parseSealedLease({ ...lease, extra: true });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(LeaseError);
      const msg = e instanceof Error ? e.message : String(e);
      expect(msg).not.toContain(SECRET);
      expect(msg).not.toContain(lease.ct);
    }
  });
});

describe("listener lease ingest", () => {
  let base: string;
  const envBackup = { ...process.env };

  beforeEach(() => {
    base = tmpBase();
    process.env.ABRA_REMOTE_UNLOCK = "1";
    process.env.ABRA_DIR = base;
  });

  afterEach(() => {
    process.env = { ...envBackup };
    fs.rmSync(base, { recursive: true, force: true });
  });

  it(`POST ${LEASE_PATH} ingests and serves while conceptually locked`, () => {
    const hub = generateSyncIdentity();
    const { key: device } = getOrCreateDeviceKey({ base });
    setHubPin(
      { deviceId: hub.id, ed25519: hub.ed25519.publicKey, x25519: hub.x25519.publicKey },
      { base },
    );
    const leaseStore = new LeaseStore({ base });
    const session = new UnlockSession({
      base,
      leaseStore,
      unlockWithKey: () => undefined,
      isLocked: () => true,
    });
    const lease = sealLease({
      hub,
      peer: { id: device.id, x25519: device.x25519.publicKey },
      project: "cryptoPnL",
      binding: { exe: "/usr/bin/bot", dev: 3, ino: 4 },
      vars: { T: { value: SECRET, secret: true, updatedAt: 1 } },
      issuedAt: Date.now(),
    });
    const outcome = session.acceptLease(lease);
    expect(outcome.httpStatus).toBe(200);
    expect(outcome.response.status).toBe("leased");
    expect(outcome.response.leaseId).toBe(lease.leaseId);
    expect(JSON.stringify(outcome)).not.toContain(SECRET);

    const revealed = leaseStore.reveal("cryptoPnL", {
      exe: "/usr/bin/bot",
      dev: 3,
      ino: 4,
    });
    expect(revealed.vars.T.value).toBe(SECRET);
  });

  it("tampered lease ingest refused", () => {
    const hub = generateSyncIdentity();
    const { key: device } = getOrCreateDeviceKey({ base });
    setHubPin(
      { deviceId: hub.id, ed25519: hub.ed25519.publicKey, x25519: hub.x25519.publicKey },
      { base },
    );
    const leaseStore = new LeaseStore({ base });
    const session = new UnlockSession({
      base,
      leaseStore,
      unlockWithKey: () => undefined,
    });
    const lease = sealLease({
      hub,
      peer: { id: device.id, x25519: device.x25519.publicKey },
      project: "demo",
      binding: { exe: "/bin/x", dev: 1, ino: 1 },
      vars: { K: { value: SECRET, secret: true, updatedAt: 1 } },
      issuedAt: Date.now(),
    });
    const bad = { ...lease, project: "other" };
    const outcome = session.acceptLease(bad);
    expect(outcome.response.status).toBe("rejected");
    expect(outcome.reason).toBe("bad-signature");
  });
});
