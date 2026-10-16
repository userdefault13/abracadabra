import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { UnlockWrap, Vault } from "../core/vault.js";
import { VAULT_UNCHANGED, decryptVault, encryptVaultForExport, withoutDeviceLocal } from "../core/vault.js";
import { generateSyncIdentity, getOrCreateSyncIdentity } from "../sync/identity.js";
import { planPeerUpsert, removePeer } from "../sync/peers.js";
import { cmdRemoteEnroll } from "../commands/remote.js";
import { getHubPin } from "./hub-pin.js";
import { readUnlockBlob, unwrapMasterKey, ReEnrollNeededError } from "./unlock-blob.js";
import {
  completeHubEnroll,
  enrollLoopback,
  EnrollError,
  planHubEnroll,
  prepareReceiverEnroll,
} from "./enroll.js";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-enroll-"));
}

/** Hub (source) + receiver vaults, mutually paired. */
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

describe("remote enroll", () => {
  let base: string;
  let masterKey: Buffer;
  let envBackup: string | undefined;

  beforeEach(() => {
    base = tmpBase();
    masterKey = crypto.randomBytes(32);
    envBackup = process.env.ABRA_REMOTE_UNLOCK;
  });

  afterEach(() => {
    masterKey.fill(0);
    fs.rmSync(base, { recursive: true, force: true });
    if (envBackup === undefined) delete process.env.ABRA_REMOTE_UNLOCK;
    else process.env.ABRA_REMOTE_UNLOCK = envBackup;
  });

  it("loopback: receiver blob + hub unlockWrap; W unwraps the blob", () => {
    const { hub, receiver, receiverId } = pairedFleet();
    const out = enrollLoopback(
      { vault: hub, peerNameOrId: "mini" },
      { vault: receiver, masterKey, base, hubNameOrId: "mbp" },
      { now: 1_700_000_000_000 },
    );

    expect(out.peerName).toBe("mini");
    expect(out.peerId).toBe(receiverId);

    const wrap = out.hubVault.syncPeers![receiverId].unlockWrap;
    expect(wrap).toBeDefined();
    expect(wrap!.v).toBe(1);
    expect(wrap!.enrolledAt).toBe(1_700_000_000_000);
    expect(wrap!.masterKeyFingerprint).toBe(out.blob.masterKeyFingerprint);

    const blob = readUnlockBlob(base);
    expect(blob).toEqual(out.blob);

    const W = Buffer.from(wrap!.wrapKey, "base64");
    const opened = unwrapMasterKey(blob!, W);
    expect(opened.equals(masterKey)).toBe(true);
    opened.fill(0);
    W.fill(0);

    const pin = getHubPin(base);
    expect(pin?.deviceId).toBe(hub.syncIdentity!.id);
    expect(pin?.ed25519).toBe(hub.syncIdentity!.ed25519.publicKey);

    const offerText = JSON.stringify(out.offer);
    expect(offerText).not.toContain(wrap!.wrapKey);
  });

  it("only paired receivers can enroll on the hub", () => {
    const { hub, receiver } = pairedFleet();
    const prepared = prepareReceiverEnroll({
      vault: receiver,
      masterKey,
      base,
      hubNameOrId: "mbp",
    });

    const peerId = Object.keys(hub.syncPeers!)[0];
    const badHub: Vault = {
      ...hub,
      syncPeers: {
        [peerId]: { ...hub.syncPeers![peerId], role: "source" },
      },
    };
    expect(() => planHubEnroll(badHub, prepared.offer)).toThrow(EnrollError);
    expect(() => planHubEnroll(badHub, prepared.offer)).toThrow(/only receivers/);
  });

  it("completeHubEnroll authenticates before updateVault (no lock across Touch ID)", async () => {
    const { hub, receiver, receiverId } = pairedFleet();
    const prepared = prepareReceiverEnroll({
      vault: receiver,
      masterKey,
      base,
      hubNameOrId: "mbp",
    });

    let stored = hub;
    const order: string[] = [];
    await completeHubEnroll(prepared.offer, "mini", {
      authenticate: async () => {
        order.push("auth");
      },
      loadVault: async () => stored,
      updateVault: async (mutator) => {
        order.push("update");
        const next = await mutator(stored);
        if (next === undefined || next === VAULT_UNCHANGED) return stored;
        stored = next;
        return stored;
      },
      now: () => 42,
    });

    expect(order).toEqual(["auth", "update"]);
    expect(stored.syncPeers![receiverId].unlockWrap?.enrolledAt).toBe(42);
  });

  it("unlockWrap is stripped from exports (device-local with syncPeers)", () => {
    const { hub, receiver, receiverId } = pairedFleet();
    const out = enrollLoopback(
      { vault: hub, peerNameOrId: "mini" },
      { vault: receiver, masterKey, base, hubNameOrId: "mbp" },
    );
    const wrap = out.hubVault.syncPeers![receiverId].unlockWrap!;
    const key = crypto.randomBytes(32);

    const exported = decryptVault(encryptVaultForExport(out.hubVault, key), key);
    expect(exported.syncPeers).toBeUndefined();
    expect(JSON.stringify(exported)).not.toContain(wrap.wrapKey);
    expect(JSON.stringify(exported)).not.toContain("unlockWrap");

    const stripped = withoutDeviceLocal(out.hubVault);
    expect(stripped.syncPeers).toBeUndefined();
    expect(JSON.stringify(stripped)).not.toContain(wrap.wrapKey);

    key.fill(0);
  });

  it("abra sync unpair clears unlockWrap (peer record deleted)", () => {
    const { hub, receiver, receiverId } = pairedFleet();
    const out = enrollLoopback(
      { vault: hub, peerNameOrId: "mini" },
      { vault: receiver, masterKey, base, hubNameOrId: "mbp" },
    );
    expect(out.hubVault.syncPeers![receiverId].unlockWrap).toBeDefined();
    const wrapKey = out.hubVault.syncPeers![receiverId].unlockWrap!.wrapKey;

    const { vault: after, removed } = removePeer(out.hubVault, "mini");
    expect(removed.peer.unlockWrap?.wrapKey).toBe(wrapKey);
    expect(after.syncPeers).toEqual({});
    expect(JSON.stringify(after)).not.toContain(wrapKey);
  });

  it("cmdRemoteEnroll requires ABRA_REMOTE_UNLOCK=1 and uses fetchOffer", async () => {
    delete process.env.ABRA_REMOTE_UNLOCK;

    const { hub, receiver } = pairedFleet();
    const prepared = prepareReceiverEnroll({
      vault: receiver,
      masterKey,
      base,
      hubNameOrId: "mbp",
    });

    let stored = hub;
    const logs: string[] = [];
    const deps = {
      authenticate: async () => {},
      loadVault: async () => stored,
      updateVault: async (m: (v: Vault) => Vault | typeof VAULT_UNCHANGED | void) => {
        const next = await m(stored);
        if (next === undefined || next === VAULT_UNCHANGED) return stored;
        stored = next;
        return stored;
      },
      fetchOffer: async () => prepared.offer,
      log: (l: string) => logs.push(l),
    };

    await expect(cmdRemoteEnroll("mini", deps)).rejects.toThrow(/ABRA_REMOTE_UNLOCK=1/);

    process.env.ABRA_REMOTE_UNLOCK = "1";
    await cmdRemoteEnroll("mini", deps);
    expect(logs.some((l) => /enrolled remote unlock for "mini"/.test(l))).toBe(true);
    expect(Object.values(stored.syncPeers!)[0].unlockWrap).toBeDefined();
  });

  it("fingerprint mismatch after master-key change → re-enroll", () => {
    const { hub, receiver } = pairedFleet();
    const out = enrollLoopback(
      { vault: hub, peerNameOrId: "mini" },
      { vault: receiver, masterKey, base, hubNameOrId: "mbp" },
    );
    const wrap = out.hubVault.syncPeers![Object.keys(out.hubVault.syncPeers!)[0]].unlockWrap!;
    const W = Buffer.from(wrap.wrapKey, "base64");
    const newMaster = crypto.randomBytes(32);
    expect(() => unwrapMasterKey(out.blob, W, { expectedMasterKey: newMaster })).toThrow(
      ReEnrollNeededError,
    );
    W.fill(0);
    newMaster.fill(0);
  });
});

describe("unlockWrap type shape", () => {
  it("satisfies UnlockWrap when enrolled", () => {
    const id = generateSyncIdentity();
    const wrap: UnlockWrap = {
      v: 1,
      wrapKey: crypto.randomBytes(32).toString("base64"),
      deviceId: id.id,
      deviceEd25519: id.ed25519.publicKey,
      deviceX25519: id.x25519.publicKey,
      masterKeyFingerprint: "abcd efgh ijkl mnop qrst uvwx yz12 3456",
      enrolledAt: 1,
    };
    expect(wrap.v).toBe(1);
  });
});
