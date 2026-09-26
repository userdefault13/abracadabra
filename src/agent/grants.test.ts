import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  mkAgentTestDir,
} from "./paths.js";
import {
  startAgent,
  stopAgent,
  type AuthorizePeerFn,
} from "./server.js";
import {
  agentUnlock,
  agentLock,
  agentGrantAdd,
  agentGrantList,
  agentGrantRevoke,
  agentGrantCheck,
  agentRequest,
} from "./client.js";
import { GrantStore, GRANT_TTL_MIN_SECONDS, GRANT_TTL_MAX_SECONDS } from "./grants.js";
import { AgentState } from "./state.js";

function makeKey(): Buffer {
  return crypto.randomBytes(32);
}

const allowPeer: AuthorizePeerFn = async () => ({
  ok: true,
  pid: process.pid,
  exe: process.execPath,
});

const denyPeer: AuthorizePeerFn = async () => ({
  ok: false,
  reason: "test_deny",
});

const callerA = { exe: "/usr/bin/client-a", dev: 1, ino: 100 };
const callerB = { exe: "/usr/bin/client-b", dev: 1, ino: 100 };
const callerAIno2 = { exe: "/usr/bin/client-a", dev: 1, ino: 200 };

describe("GrantStore (unit)", () => {
  it("check matches exact exe+dev+ino+project", () => {
    const store = new GrantStore();
    const g = store.add({ project: "p", caller: callerA, ttlSeconds: 120 });
    expect(store.check("p", callerA).granted).toBe(true);
    expect(store.check("p", callerA).grantId).toBe(g.id);
    expect(store.check("p", callerB).granted).toBe(false);
    expect(store.check("p", callerAIno2).granted).toBe(false);
    expect(store.check("other", callerA).granted).toBe(false);
  });

  it("expiry prunes and check returns false", () => {
    vi.useFakeTimers();
    const store = new GrantStore();
    store.add({ project: "p", caller: callerA, ttlSeconds: 60, now: Date.now() });
    expect(store.check("p", callerA).granted).toBe(true);
    vi.advanceTimersByTime(61_000);
    expect(store.check("p", callerA).granted).toBe(false);
    expect(store.list()).toHaveLength(0);
    vi.useRealTimers();
  });

  it("ttl bounds", () => {
    const store = new GrantStore();
    expect(() =>
      store.add({ project: "p", caller: callerA, ttlSeconds: GRANT_TTL_MIN_SECONDS - 1 }),
    ).toThrow(/ttlSeconds/);
    expect(() =>
      store.add({ project: "p", caller: callerA, ttlSeconds: GRANT_TTL_MAX_SECONDS + 1 }),
    ).toThrow(/ttlSeconds/);
    expect(
      store.add({ project: "p", caller: callerA, ttlSeconds: GRANT_TTL_MIN_SECONDS }).id,
    ).toBeTruthy();
    expect(
      store.add({ project: "p", caller: callerA, ttlSeconds: GRANT_TTL_MAX_SECONDS }).id,
    ).toBeTruthy();
  });

  it("list/revoke id|all", () => {
    const store = new GrantStore();
    const a = store.add({ project: "p", caller: callerA, ttlSeconds: 120 });
    const b = store.add({ project: "q", caller: callerB, ttlSeconds: 120 });
    expect(store.list()).toHaveLength(2);
    expect(store.revoke({ id: a.id })).toBe(1);
    expect(store.list().map((g) => g.id)).toEqual([b.id]);
    expect(store.revoke({ all: true })).toBe(1);
    expect(store.list()).toHaveLength(0);
  });

  it("AgentState.lock clears grants via onLock", () => {
    const store = new GrantStore();
    store.add({ project: "p", caller: callerA, ttlSeconds: 120 });
    const state = new AgentState({
      idleSeconds: 60,
      maxAgeSeconds: 3600,
      resolveMasterKey: async () => makeKey(),
      onLock: () => store.clear(),
    });
    return state.unlock().then(() => {
      expect(store.size()).toBe(1);
      state.lock();
      expect(store.size()).toBe(0);
    });
  });
});

describe.skipIf(process.platform === "win32")("agent grant ops", () => {
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
    masterKey = makeKey();
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_AGENT = "1";
    process.env.ABRA_AGENT_SOCKET = socketPath;
    process.env.ABRA_KEYSTORE = "keytar";
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_SKIP_BIOMETRICS = "1";
  });

  afterEach(async () => {
    await stopAgent();
    process.env = { ...envBackup };
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    vi.useRealTimers();
  });

  async function startUnlocked(extra?: { authorizePeer?: AuthorizePeerFn; idleSeconds?: number; maxAgeSeconds?: number }) {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
      authorizePeer: extra?.authorizePeer ?? allowPeer,
      idleSeconds: extra?.idleSeconds,
      maxAgeSeconds: extra?.maxAgeSeconds,
      sleepWatch: false,
    });
    await agentUnlock({ socketPath });
  }

  it("grant.add requires unlocked", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    await expect(
      agentGrantAdd({
        project: "p",
        caller: callerA,
        ttlSeconds: 120,
        socketPath,
      }),
    ).rejects.toMatchObject({ code: "locked" });
  });

  it("check matches exact identity; list/revoke; ttl bounds", async () => {
    await startUnlocked();
    const g = await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    expect(g.id).toMatch(/^[0-9a-f]{8}$/);
    expect(JSON.stringify(g)).not.toMatch(/masterKey|secret/i);

    const ok = await agentGrantCheck("demo", callerA, { socketPath });
    expect(ok.granted).toBe(true);
    expect(ok.grantId).toBe(g.id);

    expect((await agentGrantCheck("demo", callerB, { socketPath })).granted).toBe(false);
    expect((await agentGrantCheck("demo", callerAIno2, { socketPath })).granted).toBe(false);
    expect((await agentGrantCheck("other", callerA, { socketPath })).granted).toBe(false);

    const listed = await agentGrantList({ socketPath });
    expect(listed).toHaveLength(1);
    expect(listed[0].caller.exe).toBe(callerA.exe);
    expect(listed[0]).not.toHaveProperty("dev");

    expect(await agentGrantRevoke({ grantId: g.id, socketPath })).toBe(1);
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);

    await expect(
      agentGrantAdd({
        project: "demo",
        caller: callerA,
        ttlSeconds: 30,
        socketPath,
      }),
    ).rejects.toMatchObject({ code: "bad_request" });

    await expect(
      agentGrantAdd({
        project: "demo",
        caller: callerA,
        ttlSeconds: GRANT_TTL_MAX_SECONDS + 1,
        socketPath,
      }),
    ).rejects.toMatchObject({ code: "bad_request" });
  });

  it("expiry via fake timers → check false and pruned", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await startUnlocked();
    await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 60,
      socketPath,
    });
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(true);
    await vi.advanceTimersByTimeAsync(61_000);
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);
    expect(await agentGrantList({ socketPath })).toHaveLength(0);
  });

  it("abra lock clears all grants", async () => {
    await startUnlocked();
    await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    await agentLock({ socketPath });
    await agentUnlock({ socketPath });
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);
  });

  it("idle lock clears grants", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await startUnlocked({ idleSeconds: 1, maxAgeSeconds: 3600 });
    await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    await vi.advanceTimersByTimeAsync(1500);
    // Agent locked by idle — unlock and confirm grants gone
    await agentUnlock({ socketPath });
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);
  });

  it("max-age lock clears grants", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await startUnlocked({ idleSeconds: 3600, maxAgeSeconds: 2 });
    await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    await vi.advanceTimersByTimeAsync(2500);
    await agentUnlock({ socketPath });
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);
  });

  it("sleep lock clears grants", async () => {
    let onSleep: (() => void) | undefined;
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
      authorizePeer: allowPeer,
      sleepWatch: (opts) => {
        onSleep = opts.onSleep;
        return { stop: () => undefined };
      },
    });
    await agentUnlock({ socketPath });
    await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    onSleep!();
    await agentUnlock({ socketPath });
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);
  });

  it("stopAgent clears grants", async () => {
    await startUnlocked();
    await agentGrantAdd({
      project: "demo",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    await stopAgent();
    await startUnlocked();
    expect((await agentGrantCheck("demo", callerA, { socketPath })).granted).toBe(false);
  });

  it("non-abra peer → forbidden_peer for all grant ops", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
      authorizePeer: denyPeer,
      sleepWatch: false,
    });
    await expect(
      agentGrantAdd({
        project: "demo",
        caller: callerA,
        ttlSeconds: 120,
        socketPath,
      }),
    ).rejects.toMatchObject({ code: "forbidden_peer" });
    await expect(agentGrantList({ socketPath })).rejects.toMatchObject({
      code: "forbidden_peer",
    });
    await expect(
      agentGrantRevoke({ all: true, socketPath }),
    ).rejects.toMatchObject({ code: "forbidden_peer" });
    await expect(
      agentGrantCheck("demo", callerA, { socketPath }),
    ).rejects.toMatchObject({ code: "forbidden_peer" });
  });

  it("revoke all", async () => {
    await startUnlocked();
    await agentGrantAdd({
      project: "a",
      caller: callerA,
      ttlSeconds: 120,
      socketPath,
    });
    await agentGrantAdd({
      project: "b",
      caller: callerB,
      ttlSeconds: 120,
      socketPath,
    });
    expect(await agentGrantRevoke({ all: true, socketPath })).toBe(2);
    expect(await agentGrantList({ socketPath })).toHaveLength(0);
  });

  it("grant responses contain no secrets", async () => {
    await startUnlocked();
    const res = await agentRequest(
      {
        op: "grant.add",
        project: "demo",
        caller: callerA,
        ttlSeconds: 120,
      },
      { socketPath },
    );
    const raw = JSON.stringify(res);
    expect(raw).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/);
    expect(raw).not.toContain(masterKey.toString("base64"));
  });
});
