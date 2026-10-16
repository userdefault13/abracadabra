import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { VAULT_UNCHANGED, type Vault } from "../core/vault.js";
import { getOrCreateSyncIdentity } from "../sync/identity.js";
import { planPeerUpsert } from "../sync/peers.js";
import { auditLogPath } from "../remote/audit.js";
import { getOrCreateDeviceKey } from "../remote/device-key.js";
import { prepareReceiverEnroll } from "../remote/enroll.js";
import {
  UnlockSession,
  dispatchRemoteSession,
  isRemoteUnlockEnrolled,
  type RemotePath,
} from "../remote/listener.js";
import { readUnlockBlob } from "../remote/unlock-blob.js";
import { getHubPin } from "../remote/hub-pin.js";
import type { RemoteHttpsJsonFn } from "../remote/hub-client.js";
import {
  cmdRemoteDisable,
  cmdRemoteEnroll,
  cmdRemoteLock,
  cmdRemoteRevoke,
  cmdRemoteStatus,
  cmdRemoteUnlock,
  type RemoteCliDeps,
} from "./remote.js";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-remote-cli-"));
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

describe("remote CLI (loopback hub+receiver)", () => {
  let hubBase: string;
  let rxBase: string;
  let masterKey: Buffer;
  let envBackup: string | undefined;
  let locked: boolean;
  let unlockedKey: Buffer | null;

  beforeEach(() => {
    hubBase = tmpBase();
    rxBase = tmpBase();
    masterKey = crypto.randomBytes(32);
    envBackup = process.env.ABRA_REMOTE_UNLOCK;
    process.env.ABRA_REMOTE_UNLOCK = "1";
    locked = false;
    unlockedKey = null;
    getOrCreateDeviceKey({ base: rxBase });
  });

  afterEach(() => {
    masterKey.fill(0);
    unlockedKey?.fill(0);
    fs.rmSync(hubBase, { recursive: true, force: true });
    fs.rmSync(rxBase, { recursive: true, force: true });
    if (envBackup === undefined) delete process.env.ABRA_REMOTE_UNLOCK;
    else process.env.ABRA_REMOTE_UNLOCK = envBackup;
  });

  function makeSession(receiverVault: Vault): UnlockSession {
    const listenerCert =
      "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n";
    return new UnlockSession({
      base: rxBase,
      isLocked: () => locked,
      lockVault: () => {
        locked = true;
        unlockedKey?.fill(0);
        unlockedKey = null;
      },
      unlockWithKey: (k) => {
        unlockedKey = Buffer.from(k);
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
    return async ({ path, body }) => {
      const outcome = await dispatchRemoteSession(session, path as RemotePath, body);
      return { status: outcome.httpStatus, json: outcome.response };
    };
  }

  function hubDeps(
    hub: Vault,
    request: RemoteHttpsJsonFn,
    extras: Partial<RemoteCliDeps> = {},
  ): RemoteCliDeps & { mem: ReturnType<typeof memVault> } {
    const mem = memVault(hub);
    const logs: string[] = [];
    const errors: string[] = [];
    return {
      mem,
      authenticate: async () => {},
      loadVault: mem.loadVault,
      updateVault: mem.updateVault,
      now: () => Date.now(),
      log: (l) => logs.push(l),
      error: (l) => errors.push(l),
      base: () => hubBase,
      request,
      hubNameForReceiver: () => "mbp",
      ...extras,
    };
  }

  it("enroll → unlock → lock → status → revoke → disable (loopback)", async () => {
    const { hub, receiver, receiverId } = pairedFleet();
    locked = false; // enroll requires unlocked receiver
    const session = makeSession(receiver);
    const request = loopbackRequest(session);
    const deps = hubDeps(hub, request);

    await cmdRemoteEnroll("mini", {
      authenticate: deps.authenticate,
      loadVault: deps.loadVault,
      updateVault: deps.updateVault,
      now: deps.now,
      log: deps.log,
      base: hubBase,
      fetchOffer: async () => {
        const out = await request({
          host: "127.0.0.1",
          port: 7335,
          path: "/v1/remote/enroll",
          body: { op: "offer", hub: "mbp" },
        });
        expect(out.json.status).toBe("offer");
        return {
          offer: out.json.offer!,
          listenerCert: out.json.listenerCert,
        };
      },
    });

    const wrap = deps.mem.get().syncPeers![receiverId].unlockWrap;
    expect(wrap).toBeDefined();
    expect(wrap!.listenerCert).toContain("BEGIN CERTIFICATE");
    expect(readUnlockBlob(rxBase)).not.toBeNull();
    expect(getHubPin(rxBase)).not.toBeNull();
    expect(isRemoteUnlockEnrolled(rxBase)).toBe(true);

    // Receiver locked; hub unlocks with one Touch ID (authenticate stub).
    locked = true;
    const unlockResults = await cmdRemoteUnlock({ peers: "mini" }, deps);
    expect(unlockResults).toEqual([{ peer: "mini", ok: true }]);
    expect(locked).toBe(false);
    expect(unlockedKey!.equals(masterKey)).toBe(true);

    const lockResults = await cmdRemoteLock({ all: true }, deps);
    expect(lockResults).toEqual([{ peer: "mini", ok: true }]);
    expect(locked).toBe(true);

    const rows = await cmdRemoteStatus(deps);
    expect(rows).toEqual([
      { peer: "mini", enrolled: true, reachable: true, locked: true },
    ]);

    await cmdRemoteRevoke("mini", deps);
    expect(deps.mem.get().syncPeers![receiverId].unlockWrap).toBeUndefined();

    let disabled = false;
    await cmdRemoteDisable({
      ...deps,
      base: () => rxBase,
      afterDisable: () => {
        disabled = true;
      },
    });
    expect(disabled).toBe(true);
    expect(readUnlockBlob(rxBase)).toBeNull();
    expect(getHubPin(rxBase)).toBeNull();
    expect(isRemoteUnlockEnrolled(rxBase)).toBe(false);

    // Audit logs on both sides (hub enroll/unlock/lock/revoke; receiver enroll/unlock/lock/disable)
    const hubAudit = fs.readFileSync(auditLogPath(hubBase), "utf8").trim().split("\n");
    const rxAudit = fs.readFileSync(auditLogPath(rxBase), "utf8").trim().split("\n");
    expect(hubAudit.some((l) => l.includes('"op":"enroll"') && l.includes('"result":"ok"'))).toBe(
      true,
    );
    expect(hubAudit.some((l) => l.includes('"op":"unlock"'))).toBe(true);
    expect(hubAudit.some((l) => l.includes('"op":"lock"'))).toBe(true);
    expect(hubAudit.some((l) => l.includes('"op":"revoke"'))).toBe(true);
    expect(rxAudit.some((l) => l.includes('"op":"enroll"'))).toBe(true);
    expect(rxAudit.some((l) => l.includes('"op":"response"') || l.includes('"result":"unlocked"'))).toBe(
      true,
    );
    // Never log wrap key material
    const allAudit = hubAudit.concat(rxAudit).join("\n");
    expect(allAudit).not.toContain(wrap!.wrapKey);
  });

  it("unlock batch: one authenticate, parallel per-peer results", async () => {
    const { hub, receiver, hubId, receiverId } = pairedFleet();
    // Second receiver peer on hub
    const otherId = crypto.randomUUID();
    const otherKeys = getOrCreateSyncIdentity({ version: 1, projects: {}, connections: {} }).vault
      .syncIdentity!;
    let hubVault = planPeerUpsert(hub, {
      id: otherId,
      name: "box2",
      ed25519: otherKeys.ed25519.publicKey,
      x25519: otherKeys.x25519.publicKey,
      role: "receiver",
      address: "127.0.0.1",
    }).vault;

    locked = false;
    const session = makeSession(receiver);
    const request = loopbackRequest(session);

    // Enroll mini only
    const deps = hubDeps(hubVault, request);
    await cmdRemoteEnroll("mini", {
      authenticate: deps.authenticate,
      loadVault: deps.loadVault,
      updateVault: deps.updateVault,
      log: deps.log,
      base: hubBase,
      fetchOffer: async () => {
        const out = await request({
          host: "127.0.0.1",
          port: 7335,
          path: "/v1/remote/enroll",
          body: { op: "offer", hub: "mbp" },
        });
        return { offer: out.json.offer!, listenerCert: out.json.listenerCert };
      },
    });
    hubVault = deps.mem.get();
    expect(hubVault.syncPeers![receiverId].unlockWrap).toBeDefined();
    expect(hubVault.syncPeers![otherId]?.unlockWrap).toBeUndefined();

    let authCount = 0;
    locked = true;
    const unlockDeps = hubDeps(hubVault, request, {
      authenticate: async () => {
        authCount += 1;
      },
    });
    const results = await cmdRemoteUnlock({ peers: "mini" }, unlockDeps);
    expect(authCount).toBe(1);
    expect(results).toEqual([{ peer: "mini", ok: true }]);
    void hubId;
  });

  it("hub offline path: disable/revoke are local; status shows unreachable", async () => {
    const { hub, receiver, receiverId } = pairedFleet();
    locked = false;
    const session = makeSession(receiver);
    const request = loopbackRequest(session);
    const deps = hubDeps(hub, request);

    await cmdRemoteEnroll("mini", {
      authenticate: deps.authenticate,
      loadVault: deps.loadVault,
      updateVault: deps.updateVault,
      log: deps.log,
      base: hubBase,
      fetchOffer: async () => {
        const out = await request({
          host: "127.0.0.1",
          port: 7335,
          path: "/v1/remote/enroll",
          body: { op: "offer", hub: "mbp" },
        });
        return { offer: out.json.offer!, listenerCert: out.json.listenerCert };
      },
    });

    // Simulate unreachable peer
    const down: RemoteHttpsJsonFn = async () => {
      throw new Error("ECONNREFUSED");
    };
    const statusDeps = hubDeps(deps.mem.get(), down);
    const rows = await cmdRemoteStatus(statusDeps);
    expect(rows[0]).toMatchObject({
      peer: "mini",
      enrolled: true,
      reachable: false,
      locked: null,
      reason: "unreachable",
    });

    // Local revoke still works
    await cmdRemoteRevoke("mini", statusDeps);
    expect(statusDeps.mem.get().syncPeers![receiverId].unlockWrap).toBeUndefined();

    // Local disable still works (receiver) without hub
    await cmdRemoteDisable({
      authenticate: async () => {},
      loadVault: async () => receiver,
      updateVault: async (m) => (await m(receiver)) as Vault,
      base: () => rxBase,
      log: () => {},
    });
    expect(readUnlockBlob(rxBase)).toBeNull();
  });

  it("requires ABRA_REMOTE_UNLOCK=1", async () => {
    delete process.env.ABRA_REMOTE_UNLOCK;
    const { hub } = pairedFleet();
    const deps = hubDeps(hub, async () => ({ status: 0, json: { status: "rejected" } }));
    await expect(cmdRemoteUnlock({ all: true }, deps)).rejects.toThrow(/ABRA_REMOTE_UNLOCK=1/);
    await expect(cmdRemoteLock({ all: true }, deps)).rejects.toThrow(/ABRA_REMOTE_UNLOCK=1/);
    await expect(cmdRemoteRevoke("mini", deps)).rejects.toThrow(/ABRA_REMOTE_UNLOCK=1/);
    await expect(cmdRemoteDisable(deps)).rejects.toThrow(/ABRA_REMOTE_UNLOCK=1/);
  });

  it("refuses --keep-alive (no silent re-unlock loop)", async () => {
    const { hub } = pairedFleet();
    const deps = hubDeps(hub, async () => ({ status: 0, json: { status: "rejected" } }));
    await expect(cmdRemoteUnlock({ all: true, keepAlive: true }, deps)).rejects.toThrow(
      /--keep-alive is not supported/,
    );
  });
});
