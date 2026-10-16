import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  agentGrantCheck,
  agentLeaseReveal,
  agentLock,
  agentUnlock,
} from "./client.js";
import { LeaseStore, leaseFilePath, leasesDir } from "./lease-store.js";
import { mkAgentTestDir } from "./paths.js";
import { startAgent, stopAgent, type AuthorizePeerFn } from "./server.js";
import { getOrCreateDeviceKey } from "../remote/device-key.js";
import { setHubPin } from "../remote/hub-pin.js";
import {
  LEASE_DEFAULT_TTL_SECONDS,
  sealLease,
  type SealedLease,
} from "../remote/lease.js";
import { generateSyncIdentity } from "../sync/identity.js";

const posix = process.platform !== "win32";

const SECRET_VALUE = "super-secret-lease-value-do-not-log";
const callerA = { exe: "/usr/bin/bot-a", dev: 1, ino: 100 };
const callerB = { exe: "/usr/bin/bot-b", dev: 1, ino: 100 };

const allowPeer: AuthorizePeerFn = async () => ({
  ok: true,
  pid: process.pid,
  exe: process.execPath,
});

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-lease-"));
}

function enrollLocal(base: string, hub = generateSyncIdentity()) {
  const { key: device } = getOrCreateDeviceKey({ base });
  setHubPin(
    { deviceId: hub.id, ed25519: hub.ed25519.publicKey, x25519: hub.x25519.publicKey },
    { base },
  );
  return { hub, device };
}

function makeLease(
  hub: ReturnType<typeof generateSyncIdentity>,
  device: { id: string; x25519: { publicKey: string } },
  opts: {
    project?: string;
    binding?: typeof callerA;
    ttlSeconds?: number;
    issuedAt?: number;
    secret?: string;
    leaseId?: string;
  } = {},
): SealedLease {
  return sealLease({
    hub,
    peer: { id: device.id, x25519: device.x25519.publicKey },
    project: opts.project ?? "cryptoPnL",
    binding: opts.binding ?? callerA,
    vars: {
      API_KEY: {
        value: opts.secret ?? SECRET_VALUE,
        secret: true,
        updatedAt: opts.issuedAt ?? 1_700_000_000_000,
      },
    },
    issuedAt: opts.issuedAt ?? 1_700_000_000_000,
    ttlSeconds: opts.ttlSeconds ?? LEASE_DEFAULT_TTL_SECONDS,
    leaseId: opts.leaseId,
  });
}

describe("LeaseStore", () => {
  const envBackup = { ...process.env };
  let base: string;
  let logs: string[];

  beforeEach(() => {
    base = tmpBase();
    logs = [];
    process.env.ABRA_REMOTE_UNLOCK = "1";
    process.env.ABRA_DIR = base;
  });

  afterEach(() => {
    process.env = { ...envBackup };
    fs.rmSync(base, { recursive: true, force: true });
  });

  function store(now = () => 1_700_000_000_000): LeaseStore {
    return new LeaseStore({
      base,
      now,
      log: (line) => logs.push(line),
    });
  }

  it("serve while locked (reveal after ingest)", () => {
    const { hub, device } = enrollLocal(base);
    const lease = makeLease(hub, device);
    const s = store();
    s.ingest(lease);
    const revealed = s.reveal("cryptoPnL", callerA);
    expect(revealed.vars.API_KEY.value).toBe(SECRET_VALUE);
    expect(revealed.leaseId).toBe(lease.leaseId);
  });

  it("wrong binary refused", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    s.ingest(makeLease(hub, device));
    expect(() => s.reveal("cryptoPnL", callerB)).toThrow(/binding|caller/i);
  });

  it("expired refused and purged", () => {
    const { hub, device } = enrollLocal(base);
    const issuedAt = 1_700_000_000_000;
    const lease = makeLease(hub, device, { issuedAt, ttlSeconds: 60 });
    const s = store(() => issuedAt);
    s.ingest(lease);
    expect(fs.existsSync(leaseFilePath(lease.leaseId, base))).toBe(true);

    const later = store(() => issuedAt + 61_000);
    expect(() => later.reveal("cryptoPnL", callerA)).toThrow(/expir|project/i);
    expect(fs.existsSync(leaseFilePath(lease.leaseId, base))).toBe(false);
  });

  it("tampered refused", () => {
    const { hub, device } = enrollLocal(base);
    const lease = makeLease(hub, device);
    const s = store();
    s.ingest(lease);
    const file = leaseFilePath(lease.leaseId, base);
    const raw = JSON.parse(fs.readFileSync(file, "utf8")) as SealedLease;
    raw.project = "cryptoPnL-evil";
    fs.writeFileSync(file, `${JSON.stringify(raw)}\n`, { mode: 0o600 });
    expect(() => s.reveal("cryptoPnL-evil", callerA)).toThrow(/signature|tamper|invalid/i);
  });

  it("other project refused", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    s.ingest(makeLease(hub, device, { project: "cryptoPnL" }));
    expect(() => s.reveal("other-proj", callerA)).toThrow(/project/i);
  });

  it("secrets never in logs", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    s.ingest(makeLease(hub, device));
    s.reveal("cryptoPnL", callerA);
    const joined = logs.join("\n");
    expect(joined).not.toContain(SECRET_VALUE);
    expect(joined).not.toMatch(/super-secret/);
  });

  it("lease file is not plaintext", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    const lease = makeLease(hub, device);
    s.ingest(lease);
    const text = fs.readFileSync(leaseFilePath(lease.leaseId, base), "utf8");
    expect(text).not.toContain(SECRET_VALUE);
    expect(text).toContain('"ct"');
    expect(text).toContain('"sig"');
    if (posix) {
      expect(fs.statSync(leaseFilePath(lease.leaseId, base)).mode & 0o777).toBe(0o600);
      expect(fs.statSync(leasesDir(base)).mode & 0o777).toBe(0o700);
    }
  });

  it("replaces older lease for same project+binding", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    const first = makeLease(hub, device, { secret: "first-value-aaaa" });
    const second = makeLease(hub, device, {
      secret: "second-value-bbbb",
      leaseId: undefined,
    });
    expect(first.leaseId).not.toBe(second.leaseId);
    s.ingest(first);
    const r = s.ingest(second);
    expect(r.replaced).toBe(1);
    expect(fs.existsSync(leaseFilePath(first.leaseId, base))).toBe(false);
    expect(s.reveal("cryptoPnL", callerA).vars.API_KEY.value).toBe("second-value-bbbb");
  });

  it("survives conceptual vault lock (store has no clear-on-lock)", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    s.ingest(makeLease(hub, device));
    // GrantStore clears on lock; LeaseStore must still serve.
    expect(s.check("cryptoPnL", callerA).granted).toBe(true);
    expect(s.reveal("cryptoPnL", callerA).vars.API_KEY.value).toBe(SECRET_VALUE);
  });

  it.skipIf(!posix)("fails closed on group/world-readable lease file (POSIX)", () => {
    const { hub, device } = enrollLocal(base);
    const s = store();
    const lease = makeLease(hub, device);
    s.ingest(lease);
    fs.chmodSync(leaseFilePath(lease.leaseId, base), 0o644);
    // findMatching/readFile returns null on bad perms → reveal refuses
    expect(() => s.reveal("cryptoPnL", callerA)).toThrow();
  });
});

describe.skipIf(process.platform === "win32")("agent lease.reveal while locked", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";
  let socketPath = "";
  let vaultPath = "";
  let masterKey: Buffer;

  beforeEach(async () => {
    await stopAgent();
    tmpDir = mkAgentTestDir();
    socketPath = path.join(tmpDir, "agent.sock");
    vaultPath = path.join(tmpDir, "vault.enc");
    masterKey = Buffer.alloc(32, 7);
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_AGENT = "1";
    process.env.ABRA_AGENT_SOCKET = socketPath;
    process.env.ABRA_KEYSTORE = "keytar";
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_REMOTE_UNLOCK = "1";
  });

  afterEach(async () => {
    await stopAgent();
    process.env = { ...envBackup };
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("serves lease while agent locked; wrong binary refused", async () => {
    const { hub, device } = enrollLocal(tmpDir);
    const lease = makeLease(hub, device, { issuedAt: Date.now() });
    const s = new LeaseStore({ base: tmpDir });
    s.ingest(lease);

    await startAgent({
      socketPath,
      resolveMasterKey: async () => Buffer.from(masterKey),
      vaultPath: () => vaultPath,
      authorizePeer: allowPeer,
      sleepWatch: false,
      syncInbox: false,
      remoteUnlock: false,
    });
    // Start unlocked then lock — leases must still serve.
    await agentUnlock({ socketPath });
    await agentLock({ socketPath });

    const check = await agentGrantCheck("cryptoPnL", callerA, { socketPath });
    expect(check.granted).toBe(true);
    expect(check.grantId).toBe(lease.leaseId);

    const revealed = await agentLeaseReveal({
      project: "cryptoPnL",
      caller: callerA,
      socketPath,
    });
    expect(revealed.vars.API_KEY).toBe(SECRET_VALUE);

    await expect(
      agentLeaseReveal({ project: "cryptoPnL", caller: callerB, socketPath }),
    ).rejects.toMatchObject({ code: "bad_request" });

    await expect(
      agentLeaseReveal({ project: "other", caller: callerA, socketPath }),
    ).rejects.toMatchObject({ code: "bad_request" });
  });
});
