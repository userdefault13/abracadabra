import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { VAULT_UNCHANGED, type Vault } from "../core/vault.js";
import { getOrCreateSyncIdentity } from "../sync/identity.js";
import { planPeerUpsert } from "../sync/peers.js";
import { LeaseStore } from "../agent/lease-store.js";
import { auditLogPath } from "../remote/audit.js";
import { getOrCreateDeviceKey } from "../remote/device-key.js";
import { prepareReceiverEnroll } from "../remote/enroll.js";
import { listHubLeaseRecords } from "../remote/hub-leases.js";
import {
  LEASE_DEFAULT_TTL_SECONDS,
  LeaseError,
  parseLeaseTtl,
} from "../remote/lease.js";
import {
  UnlockSession,
  dispatchRemoteSession,
  type RemotePath,
} from "../remote/listener.js";
import type { RemoteHttpsJsonFn } from "../remote/hub-client.js";
import { cmdRemoteEnroll, cmdRemoteRevoke, type RemoteCliDeps } from "./remote.js";
import { cmdSyncUnpair, type SyncDeps } from "./sync.js";
import {
  cmdLeaseBindInfo,
  cmdLeaseGrant,
  cmdLeaseRenew,
  cmdLeaseRevoke,
  parseLeaseBinSpec,
  type LeaseCliDeps,
} from "./lease.js";

const SECRET = "lease-cli-secret-value-xyz";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-lease-cli-"));
}

function pairedFleet(): {
  hub: Vault;
  receiver: Vault;
  hubId: string;
  receiverId: string;
} {
  const hubBase = getOrCreateSyncIdentity({ version: 1, projects: {}, connections: {} }).vault;
  const receiverBase = getOrCreateSyncIdentity({ version: 1, projects: {}, connections: {} }).vault;
  const hubId = hubBase.syncIdentity!.id;
  const receiverId = receiverBase.syncIdentity!.id;

  const hub = planPeerUpsert(hubBase, {
    id: receiverId,
    name: "mini",
    ed25519: receiverBase.syncIdentity!.ed25519.publicKey,
    x25519: receiverBase.syncIdentity!.x25519.publicKey,
    role: "receiver",
    address: "127.0.0.1",
  }).vault;

  hub.projects = {
    cryptoPnL: {
      createdAt: Date.now(),
      vars: {
        API_KEY: { value: SECRET, secret: true, updatedAt: Date.now() },
      },
    },
  };

  const receiver = planPeerUpsert(receiverBase, {
    id: hubId,
    name: "mbp",
    ed25519: hubBase.syncIdentity!.ed25519.publicKey,
    x25519: hubBase.syncIdentity!.x25519.publicKey,
    role: "source",
  }).vault;

  return { hub, receiver, hubId, receiverId };
}

function memVault(initial: Vault): {
  loadVault: () => Promise<Vault>;
  updateVault: RemoteCliDeps["updateVault"];
  get: () => Vault;
} {
  let stored = structuredClone(initial);
  return {
    get: () => stored,
    loadVault: async () => structuredClone(stored),
    updateVault: async (mutator) => {
      const next = await mutator(structuredClone(stored));
      if (next === undefined || next === VAULT_UNCHANGED) return stored;
      stored = next as Vault;
      return stored;
    },
  };
}

describe("parseLeaseTtl / bind-info", () => {
  it("default unit seconds; supports d; refuses > 7d", () => {
    expect(parseLeaseTtl("7d")).toBe(LEASE_DEFAULT_TTL_SECONDS);
    expect(parseLeaseTtl("24h")).toBe(24 * 3600);
    expect(() => parseLeaseTtl("8d")).toThrow(LeaseError);
    expect(() => parseLeaseTtl("8d")).toThrow(/at most 7d/);
  });

  it("parseLeaseBinSpec accepts JSON and exe@dev:ino", () => {
    expect(parseLeaseBinSpec('{"exe":"/bin/x","dev":1,"ino":2}')).toEqual({
      exe: "/bin/x",
      dev: 1,
      ino: 2,
    });
    expect(parseLeaseBinSpec("/usr/bin/bot@3:4")).toEqual({
      exe: "/usr/bin/bot",
      dev: 3,
      ino: 4,
    });
  });
});

describe("lease CLI (loopback hub+receiver)", () => {
  let hubBase: string;
  let rxBase: string;
  let masterKey: Buffer;
  let envBackup: NodeJS.ProcessEnv;
  let locked: boolean;
  let receiverVault: Vault;
  let leaseStore: LeaseStore;

  beforeEach(() => {
    hubBase = tmpBase();
    rxBase = tmpBase();
    masterKey = crypto.randomBytes(32);
    envBackup = { ...process.env };
    process.env.ABRA_REMOTE_UNLOCK = "1";
    locked = true;
    getOrCreateDeviceKey({ base: rxBase });
    leaseStore = new LeaseStore({ base: rxBase });
  });

  afterEach(() => {
    masterKey.fill(0);
    process.env = { ...envBackup };
    fs.rmSync(hubBase, { recursive: true, force: true });
    fs.rmSync(rxBase, { recursive: true, force: true });
  });

  function makeSession(): UnlockSession {
    const listenerCert =
      "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n";
    return new UnlockSession({
      base: rxBase,
      leaseStore,
      isLocked: () => locked,
      lockVault: () => {
        locked = true;
      },
      unlockWithKey: () => {
        locked = false;
      },
      listenerCert: () => listenerCert,
      prepareEnrollOffer: (hubNameOrId) => {
        const prepared = prepareReceiverEnroll({
          vault: receiverVault,
          masterKey,
          base: rxBase,
          hubNameOrId,
        });
        return prepared.offer;
      },
    });
  }

  function loopbackRequest(session: UnlockSession): RemoteHttpsJsonFn {
    return async ({ path: p, body }) => {
      const outcome = await dispatchRemoteSession(session, p as RemotePath, body);
      return { status: outcome.httpStatus, json: outcome.response };
    };
  }

  function leaseDeps(
    hub: Vault,
    request: RemoteHttpsJsonFn,
  ): LeaseCliDeps & { mem: ReturnType<typeof memVault>; logs: string[]; errors: string[] } {
    const mem = memVault(hub);
    const logs: string[] = [];
    const errors: string[] = [];
    return {
      mem,
      logs,
      errors,
      authenticate: async () => {},
      loadVault: mem.loadVault,
      now: () => Date.now(),
      log: (l) => logs.push(l),
      error: (l) => errors.push(l),
      base: () => hubBase,
      request,
    };
  }

  async function enroll(hub: Vault, request: RemoteHttpsJsonFn): Promise<Vault> {
    locked = false;
    const mem = memVault(hub);
    await cmdRemoteEnroll("mini", {
      authenticate: async () => {},
      loadVault: mem.loadVault,
      updateVault: mem.updateVault,
      now: () => Date.now(),
      log: () => {},
      base: hubBase,
      fetchOffer: async () => {
        const out = await request({
          host: "127.0.0.1",
          port: 7335,
          path: "/v1/remote/enroll",
          body: { op: "offer", hub: "mbp" },
        });
        if (out.json.status !== "offer" || !out.json.offer) {
          throw new Error(out.json.reason ?? "enroll failed");
        }
        return { offer: out.json.offer, listenerCert: out.json.listenerCert };
      },
    });
    locked = true;
    return mem.get();
  }

  it("grant → serve while locked; values never in logs", async () => {
    const fleet = pairedFleet();
    receiverVault = fleet.receiver;
    const session = makeSession();
    const request = loopbackRequest(session);
    const enrolled = await enroll(fleet.hub, request);
    const ld = leaseDeps(enrolled, request);

    const granted = await cmdLeaseGrant(
      "cryptoPnL",
      { peer: "mini", bin: "/bin/bot@1:2", ttl: "7d" },
      ld,
    );
    expect(granted.leaseId).toBeTruthy();
    expect(locked).toBe(true);

    const revealed = leaseStore.reveal("cryptoPnL", {
      exe: "/bin/bot",
      dev: 1,
      ino: 2,
    });
    expect(revealed.vars.API_KEY.value).toBe(SECRET);

    const joined = [...ld.logs, ...ld.errors].join("\n");
    expect(joined).not.toContain(SECRET);
    expect(JSON.stringify(listHubLeaseRecords(hubBase))).not.toContain(SECRET);
    if (fs.existsSync(auditLogPath(hubBase))) {
      expect(fs.readFileSync(auditLogPath(hubBase), "utf8")).not.toContain(SECRET);
    }
    if (fs.existsSync(auditLogPath(rxBase))) {
      expect(fs.readFileSync(auditLogPath(rxBase), "utf8")).not.toContain(SECRET);
    }
  });

  it("revoke removes lease on receiver and hub registry", async () => {
    const fleet = pairedFleet();
    receiverVault = fleet.receiver;
    const session = makeSession();
    const request = loopbackRequest(session);
    const enrolled = await enroll(fleet.hub, request);
    const ld = leaseDeps(enrolled, request);

    const { leaseId } = await cmdLeaseGrant(
      "cryptoPnL",
      { peer: "mini", bin: "/bin/bot@1:2" },
      ld,
    );
    expect(leaseStore.listPublic()).toHaveLength(1);

    await cmdLeaseRevoke(leaseId, {}, leaseDeps(ld.mem.get(), request));
    expect(leaseStore.listPublic()).toHaveLength(0);
    expect(listHubLeaseRecords(hubBase)).toHaveLength(0);
  });

  it("renew extends expiry", async () => {
    const fleet = pairedFleet();
    receiverVault = fleet.receiver;
    const session = makeSession();
    const request = loopbackRequest(session);
    const enrolled = await enroll(fleet.hub, request);
    const ld = leaseDeps(enrolled, request);

    await cmdLeaseGrant("cryptoPnL", { peer: "mini", bin: "/bin/bot@1:2" }, ld);
    const before = listHubLeaseRecords(hubBase)[0]!;
    const renewLd = leaseDeps(ld.mem.get(), request);
    const { renewed, failed } = await cmdLeaseRenew({ all: true }, renewLd);
    expect(failed).toBe(0);
    expect(renewed).toBe(1);
    const after = listHubLeaseRecords(hubBase)[0]!;
    expect(after.leaseId).not.toBe(before.leaseId);
    expect(after.expiresAt).toBeGreaterThanOrEqual(before.expiresAt);
    expect(
      leaseStore.reveal("cryptoPnL", { exe: "/bin/bot", dev: 1, ino: 2 }).vars.API_KEY.value,
    ).toBe(SECRET);
  });

  it("TTL > 7d refused", async () => {
    const fleet = pairedFleet();
    receiverVault = fleet.receiver;
    const session = makeSession();
    const request = loopbackRequest(session);
    const enrolled = await enroll(fleet.hub, request);
    const ld = leaseDeps(enrolled, request);

    await expect(
      cmdLeaseGrant("cryptoPnL", { peer: "mini", bin: "/bin/bot@1:2", ttl: "8d" }, ld),
    ).rejects.toThrow(/at most 7d/);
  });

  it("sync unpair revokes leases", async () => {
    const fleet = pairedFleet();
    receiverVault = fleet.receiver;
    const session = makeSession();
    const request = loopbackRequest(session);
    const enrolled = await enroll(fleet.hub, request);
    const ld = leaseDeps(enrolled, request);
    await cmdLeaseGrant("cryptoPnL", { peer: "mini", bin: "/bin/bot@1:2" }, ld);
    expect(leaseStore.listPublic()).toHaveLength(1);

    const syncMem = memVault(ld.mem.get());
    const syncDeps: SyncDeps = {
      abraDir: () => hubBase,
      detectTailscale: async () => null,
      agentInboxStatus: async () => null,
      authenticate: async () => {},
      loadVault: syncMem.loadVault,
      updateVault: syncMem.updateVault,
      confirm: async () => true,
      promptPin: async () => "000000",
      createTls: () => ({
        key: "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----\n",
        cert: "-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n",
        fingerprint: "aa:bb",
      }),
      generatePin: () => "123456",
      hostname: () => "test",
      now: () => Date.now(),
      randomBytes: (n) => crypto.randomBytes(n),
      log: () => {},
      remoteRequest: request,
      error: () => {},
    };
    await cmdSyncUnpair("mini", { yes: true }, syncDeps);
    expect(leaseStore.listPublic()).toHaveLength(0);
    expect(listHubLeaseRecords(hubBase)).toHaveLength(0);
  });

  it("remote revoke also revokes leases", async () => {
    const fleet = pairedFleet();
    receiverVault = fleet.receiver;
    const session = makeSession();
    const request = loopbackRequest(session);
    const enrolled = await enroll(fleet.hub, request);
    const ld = leaseDeps(enrolled, request);
    await cmdLeaseGrant("cryptoPnL", { peer: "mini", bin: "/bin/bot@1:2" }, ld);
    expect(leaseStore.listPublic()).toHaveLength(1);

    const mem = memVault(ld.mem.get());
    await cmdRemoteRevoke("mini", {
      authenticate: async () => {},
      loadVault: mem.loadVault,
      updateVault: mem.updateVault,
      now: () => Date.now(),
      log: () => {},
      error: () => {},
      base: () => hubBase,
      request,
    });
    expect(leaseStore.listPublic()).toHaveLength(0);
    expect(listHubLeaseRecords(hubBase)).toHaveLength(0);
  });

  it.skipIf(process.platform === "win32")("bind-info resolves local file identity", () => {
    const bin = path.join(rxBase, "fake-bot");
    fs.writeFileSync(bin, "#!/bin/sh\n", { mode: 0o755 });
    process.env.ABRA_DIR = rxBase;
    process.env.ABRA_REMOTE_UNLOCK = "1";
    const binding = cmdLeaseBindInfo(bin, { json: true });
    expect(binding.exe).toBe(fs.realpathSync(bin));
    expect(typeof binding.dev).toBe("number");
    expect(typeof binding.ino).toBe("number");
  });
});
