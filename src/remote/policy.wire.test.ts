import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getOrCreateSyncIdentity } from "../sync/identity.js";
import { planPeerUpsert } from "../sync/peers.js";
import type { Vault } from "../core/vault.js";
import { getOrCreateDeviceKey } from "./device-key.js";
import { enrollLoopback } from "./enroll.js";
import { remoteUnlockLoopback } from "./hub-client.js";
import { UnlockSession } from "./listener.js";
import {
  buildUnlockResponse,
  parseUnlockWireMessage,
  type UnlockPolicy,
} from "./wire.js";
import type { AppliedUnlockPolicy } from "./policy.js";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-policy-wire-"));
}

function pairedFleet(): {
  hub: Vault;
  receiver: Vault;
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

  return { hub, receiver };
}

describe("relock policy on unlock wire", () => {
  let base: string;
  let masterKey: Buffer;
  let envBackup: string | undefined;
  let applied: AppliedUnlockPolicy | null;

  const FIXED_NOW = 1_700_000_000_100;
  const LOCAL_CAPS = { idleSeconds: 15 * 60, maxAgeSeconds: 8 * 60 * 60 };

  beforeEach(() => {
    base = tmpBase();
    masterKey = crypto.randomBytes(32);
    applied = null;
    envBackup = process.env.ABRA_REMOTE_UNLOCK;
    process.env.ABRA_REMOTE_UNLOCK = "1";
    getOrCreateDeviceKey({ base });
  });

  afterEach(() => {
    masterKey.fill(0);
    fs.rmSync(base, { recursive: true, force: true });
    if (envBackup === undefined) delete process.env.ABRA_REMOTE_UNLOCK;
    else process.env.ABRA_REMOTE_UNLOCK = envBackup;
  });

  function enroll() {
    const { hub, receiver } = pairedFleet();
    const out = enrollLoopback(
      { vault: hub, peerNameOrId: "mini" },
      { vault: receiver, masterKey, base, hubNameOrId: "mbp" },
      { now: 1_700_000_000_000 },
    );
    return {
      hubIdentity: out.hubVault.syncIdentity!,
      unlockWrap: out.hubVault.syncPeers![out.peerId].unlockWrap!,
    };
  }

  function session(): UnlockSession {
    let locked = true;
    return new UnlockSession({
      base,
      now: () => FIXED_NOW,
      isLocked: () => locked,
      localCaps: () => LOCAL_CAPS,
      unlockWithKey: (_k, policy) => {
        applied = policy;
        locked = false;
      },
    });
  }

  it("applies clamp: shorter hub request wins", async () => {
    const h = enroll();
    const sess = session();
    const policy: UnlockPolicy = { idleSeconds: 120, maxAgeSeconds: 1800 };
    const result = await remoteUnlockLoopback({
      session: {
        issueChallenge: () => sess.issueChallenge(),
        acceptResponse: (raw) => sess.acceptResponse(raw),
      },
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      policy,
      now: () => FIXED_NOW,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.policy).toEqual({ idleSeconds: 120, maxAgeSeconds: 1800 });
    expect(applied).toEqual({ idleSeconds: 120, maxAgeSeconds: 1800 });
  });

  it("hub cannot lengthen past local caps", async () => {
    const h = enroll();
    const sess = session();
    const policy: UnlockPolicy = {
      idleSeconds: 24 * 60 * 60,
      maxAgeSeconds: 48 * 60 * 60,
    };
    const result = await remoteUnlockLoopback({
      session: {
        issueChallenge: () => sess.issueChallenge(),
        acceptResponse: (raw) => sess.acceptResponse(raw),
      },
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      policy,
      now: () => FIXED_NOW,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.policy).toEqual(LOCAL_CAPS);
    expect(applied).toEqual(LOCAL_CAPS);
  });

  it("tampering with signed policy rejects", async () => {
    const h = enroll();
    const sess = session();
    const issued = sess.issueChallenge();
    const challenge = parseUnlockWireMessage(issued.response.challenge!);
    if (challenge.op !== "challenge") throw new Error("expected challenge");

    const response = buildUnlockResponse({
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      challenge,
      policy: { idleSeconds: 60, maxAgeSeconds: 600 },
      now: FIXED_NOW,
    });

    const tampered = {
      ...response,
      policy: { idleSeconds: 24 * 60 * 60, maxAgeSeconds: 48 * 60 * 60 },
    };
    const out = await sess.acceptResponse(tampered);
    expect(out.response).toEqual({ status: "rejected", reason: "unauthorized" });
    expect(applied).toBeNull();
  });
});
