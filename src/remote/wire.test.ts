import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { Vault } from "../core/vault.js";
import { generateSyncIdentity, getOrCreateSyncIdentity } from "../sync/identity.js";
import { planPeerUpsert } from "../sync/peers.js";
import { getOrCreateDeviceKey } from "./device-key.js";
import { setHubPin } from "./hub-pin.js";
import { remoteUnlockLoopback } from "./hub-client.js";
import {
  UnlockSession,
  createUnlockRequestHandler,
  isRemoteUnlockEnrolled,
} from "./listener.js";
import { NonceCache } from "./nonce-cache.js";
import { decodeWrapKey, unwrapMasterKey } from "./unlock-blob.js";
import {
  MAX_RESPONSE_TTL_MS,
  UNLOCK_MAX_BODY_BYTES,
  UNLOCK_PATH,
  UnlockWireError,
  buildUnlockResponse,
  issueUnlockChallenge,
  openWrapKeyFromResponse,
  parseUnlockWireMessage,
  verifyUnlockChallenge,
  verifyUnlockResponse,
} from "./wire.js";
import { enrollLoopback } from "./enroll.js";

function tmpBase(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "abra-wire-"));
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

function enrollHarness(base: string, masterKey: Buffer) {
  const { hub, receiver, hubId } = pairedFleet();
  const out = enrollLoopback(
    { vault: hub, peerNameOrId: "mini" },
    { vault: receiver, masterKey, base, hubNameOrId: "mbp" },
    { now: 1_700_000_000_000 },
  );
  const unlockWrap = out.hubVault.syncPeers![out.peerId].unlockWrap!;
  return {
    hubIdentity: out.hubVault.syncIdentity!,
    unlockWrap,
    hubId,
    peerId: out.peerId,
    masterKey,
  };
}

describe("remote unlock wire", () => {
  let base: string;
  let masterKey: Buffer;
  let envBackup: string | undefined;
  let unlocked: Buffer | null;

  beforeEach(() => {
    base = tmpBase();
    masterKey = crypto.randomBytes(32);
    unlocked = null;
    envBackup = process.env.ABRA_REMOTE_UNLOCK;
    process.env.ABRA_REMOTE_UNLOCK = "1";
  });

  afterEach(() => {
    masterKey.fill(0);
    unlocked?.fill(0);
    fs.rmSync(base, { recursive: true, force: true });
    if (envBackup === undefined) delete process.env.ABRA_REMOTE_UNLOCK;
    else process.env.ABRA_REMOTE_UNLOCK = envBackup;
  });

  const FIXED_NOW = 1_700_000_000_100;

  function session(opts: { locked?: boolean; now?: () => number } = {}): UnlockSession {
    let locked = opts.locked ?? true;
    return new UnlockSession({
      base,
      now: opts.now ?? (() => FIXED_NOW),
      isLocked: () => locked,
      unlockWithKey: (k) => {
        unlocked = Buffer.from(k);
        locked = false;
      },
      log: (line) => logs.push(line),
    });
  }

  const logs: string[] = [];
  beforeEach(() => {
    logs.length = 0;
  });

  it("happy path (loopback): challenge → seal(W) → unwrap → unlock", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    const result = await remoteUnlockLoopback({
      session: {
        issueChallenge: () => sess.issueChallenge(),
        acceptResponse: (raw) => sess.acceptResponse(raw),
      },
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      now: () => FIXED_NOW,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    // Empty hub policy → receiver applies local agent caps (default 15m / 8h).
    expect(result.policy).toEqual({
      idleSeconds: 15 * 60,
      maxAgeSeconds: 8 * 60 * 60,
    });
    expect(unlocked!.equals(masterKey)).toBe(true);
    expect(isRemoteUnlockEnrolled(base)).toBe(true);
  });

  it("replay rejected", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    const issued = sess.issueChallenge();
    const challenge = parseUnlockWireMessage(issued.response.challenge!);
    expect(challenge.op).toBe("challenge");
    if (challenge.op !== "challenge") throw new Error("expected challenge");
    const response = buildUnlockResponse({
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      challenge,
      now: FIXED_NOW,
    });
    expect((await sess.acceptResponse(response)).response.status).toBe("unlocked");
    // Re-lock so "already-unlocked" does not mask replay.
    const sess2 = new UnlockSession({
      base,
      nonceCache: sess.nonces,
      now: () => FIXED_NOW,
      isLocked: () => true,
      unlockWithKey: () => {},
      log: (line) => logs.push(line),
    });
    const again = await sess2.acceptResponse(response);
    expect(again.response).toEqual({ status: "rejected", reason: "replay" });
  });

  it("expired rejected", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    const issued = sess.issueChallenge();
    const challenge = parseUnlockWireMessage(issued.response.challenge!);
    if (challenge.op !== "challenge") throw new Error("expected challenge");
    const response = buildUnlockResponse({
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      challenge,
      now: FIXED_NOW,
      expiresAt: FIXED_NOW + 1_000, // valid at build time
    });
    // Receiver clock past expiry
    const late = new UnlockSession({
      base,
      nonceCache: sess.nonces,
      now: () => response.expiresAt + 1,
      isLocked: () => true,
      unlockWithKey: () => {
        throw new Error("should not unlock");
      },
      log: (line) => logs.push(line),
    });
    const out = await late.acceptResponse(response);
    expect(out.response).toEqual({ status: "rejected", reason: "expired" });
  });

  it("wrong hub key rejected", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    const issued = sess.issueChallenge();
    const challenge = parseUnlockWireMessage(issued.response.challenge!);
    if (challenge.op !== "challenge") throw new Error("expected challenge");

    const impostor = generateSyncIdentity(FIXED_NOW);
    const response = buildUnlockResponse({
      hubIdentity: impostor,
      unlockWrap: h.unlockWrap,
      challenge,
      now: FIXED_NOW,
    });
    // Impostor's `from` won't match hub-pin; also sig won't verify against pin.
    const out = await sess.acceptResponse(response);
    expect(out.response).toEqual({ status: "rejected", reason: "unauthorized" });
  });

  it("wrong device key rejected on hub verify", () => {
    const h = enrollHarness(base, masterKey);
    const otherBase = tmpBase();
    try {
      const other = getOrCreateDeviceKey({ base: otherBase, now: 1 }).key;
      const issued = issueUnlockChallenge(other, { now: FIXED_NOW });
      expect(() =>
        verifyUnlockChallenge(issued.message, h.unlockWrap.deviceEd25519, {
          expectedDeviceId: h.unlockWrap.deviceId,
        }),
      ).toThrow(UnlockWireError);
      issued.ephPrivateRaw.fill(0);
    } finally {
      fs.rmSync(otherBase, { recursive: true, force: true });
    }
  });

  it("tampered fields rejected", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    const issued = sess.issueChallenge();
    const challenge = parseUnlockWireMessage(issued.response.challenge!);
    if (challenge.op !== "challenge") throw new Error("expected challenge");
    const response = buildUnlockResponse({
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      challenge,
      now: FIXED_NOW,
    });
    // Tamper a signed field without re-signing (keep expiresAt valid so expiry isn't the reject reason).
    const tampered = { ...response, peerId: crypto.randomUUID() };
    const out = await sess.acceptResponse(tampered);
    expect(out.response).toEqual({ status: "rejected", reason: "unauthorized" });
  });

  it("oversized/garbage input fuzz (fixed seed)", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    const rng = crypto.createHash("sha256").update("abra-remote-unlock-fuzz-v1").digest();
    let state = Buffer.from(rng);

    const nextByte = (): number => {
      state = crypto.createHash("sha256").update(state).digest();
      return state[0]!;
    };
    const nextBuf = (n: number): Buffer => {
      const out = Buffer.alloc(n);
      for (let i = 0; i < n; i++) out[i] = nextByte();
      return out;
    };

    for (let i = 0; i < 64; i++) {
      const kind = nextByte() % 5;
      let raw: unknown;
      if (kind === 0) raw = nextBuf(16 + (nextByte() % 200)).toString("base64");
      else if (kind === 1) raw = { v: 99, op: "response", junk: nextBuf(32).toString("hex") };
      else if (kind === 2) raw = null;
      else if (kind === 3) {
        raw = {
          v: 1,
          op: "response",
          from: "not-a-uuid",
          peerId: h.unlockWrap.deviceId,
          nonce: nextBuf(32).toString("base64"),
          expiresAt: Date.now() + 1000,
          policy: {},
          epk: nextBuf(32).toString("base64"),
          sealNonce: nextBuf(12).toString("base64"),
          ct: nextBuf(48).toString("base64"),
          sig: nextBuf(64).toString("base64"),
        };
      } else {
        raw = nextBuf(UNLOCK_MAX_BODY_BYTES + 100);
      }
      const out = await sess.handle(raw);
      expect(out.response.status).not.toBe("unlocked");
      expect(unlocked).toBeNull();
    }
    // Schema parse must not throw uncaught on garbage
    for (let i = 0; i < 32; i++) {
      expect(() => parseUnlockWireMessage(nextBuf(8 + (nextByte() % 40)))).toThrow(UnlockWireError);
    }
  });

  it("no secrets in logs", async () => {
    const h = enrollHarness(base, masterKey);
    const sess = session();
    await remoteUnlockLoopback({
      session: {
        issueChallenge: () => sess.issueChallenge(),
        acceptResponse: (raw) => sess.acceptResponse(raw),
      },
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      now: () => FIXED_NOW,
    });
    const joined = logs.join("\n");
    expect(joined).toMatch(/op=challenge/);
    expect(joined).toMatch(/op=response/);
    expect(joined).toMatch(/result=unlocked/);
    expect(joined).not.toContain(h.unlockWrap.wrapKey);
    expect(joined).not.toContain(masterKey.toString("base64"));
    expect(joined).not.toContain(h.hubIdentity.ed25519.privateKey);
    // Log lines are op/peer/result only
    for (const line of logs) {
      expect(line).toMatch(/^op=\w+/);
      expect(line).not.toMatch(/wrapKey|masterKey|privateKey|ct=/i);
    }
  });

  it("hub refuses response TTL > 30s", () => {
    const h = enrollHarness(base, masterKey);
    const device = getOrCreateDeviceKey({ base }).key;
    const issued = issueUnlockChallenge(device, { now: 1_000 });
    expect(() =>
      buildUnlockResponse({
        hubIdentity: h.hubIdentity,
        unlockWrap: h.unlockWrap,
        challenge: issued.message,
        now: 1_000,
        expiresAt: 1_000 + MAX_RESPONSE_TTL_MS + 1,
      }),
    ).toThrow(/30s/);
    issued.ephPrivateRaw.fill(0);
  });

  it("pure crypto: openWrapKeyFromResponse recovers W", () => {
    const h = enrollHarness(base, masterKey);
    const device = getOrCreateDeviceKey({ base }).key;
    const issued = issueUnlockChallenge(device, { now: 2_000 });
    const response = buildUnlockResponse({
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      challenge: issued.message,
      now: 2_000,
    });
    const pin = setHubPin(
      {
        deviceId: h.hubIdentity.id,
        ed25519: h.hubIdentity.ed25519.publicKey,
        x25519: h.hubIdentity.x25519.publicKey,
      },
      { base, force: true },
    );
    verifyUnlockResponse(response, pin, { now: 2_000, expectedPeerId: device.id });
    const W = openWrapKeyFromResponse(response, issued.message.epk, issued.ephPrivateRaw);
    expect(W.equals(decodeWrapKey(h.unlockWrap.wrapKey))).toBe(true);
    const opened = unwrapMasterKey(
      JSON.parse(fs.readFileSync(path.join(base, "remote", "remote-unlock.blob"), "utf8")),
      W,
    );
    expect(opened.equals(masterKey)).toBe(true);
    W.fill(0);
    opened.fill(0);
    issued.ephPrivateRaw.fill(0);
  });
});

describe("remote unlock HTTP handler (loopback)", () => {
  let base: string;
  let masterKey: Buffer;
  let envBackup: string | undefined;
  let server: http.Server | null = null;

  beforeEach(() => {
    base = tmpBase();
    masterKey = crypto.randomBytes(32);
    envBackup = process.env.ABRA_REMOTE_UNLOCK;
    process.env.ABRA_REMOTE_UNLOCK = "1";
  });

  afterEach(async () => {
    masterKey.fill(0);
    if (server) {
      await new Promise<void>((r) => server!.close(() => r()));
      server = null;
    }
    fs.rmSync(base, { recursive: true, force: true });
    if (envBackup === undefined) delete process.env.ABRA_REMOTE_UNLOCK;
    else process.env.ABRA_REMOTE_UNLOCK = envBackup;
  });

  function post(port: number, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
    const data = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          path: UNLOCK_PATH,
          method: "POST",
          headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              json: JSON.parse(Buffer.concat(chunks).toString("utf8")),
            }),
          );
        },
      );
      req.on("error", reject);
      req.end(data);
    });
  }

  it("happy path over HTTP loopback", async () => {
    const h = enrollHarness(base, masterKey);
    let unlocked: Buffer | null = null;
    const sess = new UnlockSession({
      base,
      isLocked: () => unlocked === null,
      unlockWithKey: (k) => {
        unlocked = Buffer.from(k);
      },
    });
    const handler = createUnlockRequestHandler((raw) => sess.handle(raw));
    server = http.createServer(handler);
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;

    const ch = await post(port, { op: "challenge" });
    expect(ch.status).toBe(200);
    expect(ch.json.status).toBe("challenge");
    const challenge = parseUnlockWireMessage(ch.json.challenge);
    if (challenge.op !== "challenge") throw new Error("expected challenge");

    const response = buildUnlockResponse({
      hubIdentity: h.hubIdentity,
      unlockWrap: h.unlockWrap,
      challenge,
      now: Date.now(),
    });
    const un = await post(port, response);
    expect(un).toEqual({
      status: 200,
      json: {
        status: "unlocked",
        policy: { idleSeconds: 15 * 60, maxAgeSeconds: 8 * 60 * 60 },
      },
    });
    expect(unlocked!.equals(masterKey)).toBe(true);
    unlocked!.fill(0);
  });

  it("rejects oversized body", async () => {
    enrollHarness(base, masterKey);
    const sess = new UnlockSession({
      base,
      unlockWithKey: () => {},
    });
    const handler = createUnlockRequestHandler((raw) => sess.handle(raw), {
      maxBodyBytes: 256,
    });
    server = http.createServer(handler);
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    const big = "x".repeat(512);
    const out = await post(port, { op: "response", pad: big });
    expect(out.status).toBe(413);
    expect(out.json).toEqual({ status: "rejected", reason: "too-large" });
  });
});

describe("NonceCache", () => {
  it("rejects duplicate pending and tracks used", () => {
    const c = new NonceCache({
      pendingTtlMs: 60_000,
      usedRetentionMs: 60_000,
      maxPending: 10,
      maxUsed: 10,
    });
    const nonce = crypto.randomBytes(32).toString("base64");
    const eph = crypto.randomBytes(32);
    expect(
      c.addPending(
        nonce,
        { ephPrivateRaw: eph, ephPublic: "x", deviceId: crypto.randomUUID(), createdAt: 1 },
        1,
      ),
    ).toBe(true);
    expect(
      c.addPending(
        nonce,
        { ephPrivateRaw: crypto.randomBytes(32), ephPublic: "y", deviceId: crypto.randomUUID(), createdAt: 1 },
        1,
      ),
    ).toBe(false);
    const taken = c.takePending(nonce, 2)!;
    expect(taken.ephPublic).toBe("x");
    c.markUsed(nonce, 2);
    expect(c.isUsed(nonce, 3)).toBe(true);
    expect(c.takePending(nonce, 3)).toBeNull();
    taken.ephPrivateRaw.fill(0);
  });
});
