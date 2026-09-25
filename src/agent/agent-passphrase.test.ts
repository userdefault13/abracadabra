import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import {
  mkAgentTestDir,
  resolveMaxAgeSeconds,
  DEFAULT_MAX_AGE_SECONDS,
} from "./paths.js";
import { AgentState } from "./state.js";
import {
  startAgent,
  stopAgent,
  type AuthorizePeerFn,
} from "./server.js";
import {
  agentStatus,
  agentUnlock,
  agentUnlockKey,
  agentLock,
  agentVaultLoad,
  agentRequest,
  loadVaultViaAgent,
  isAgentUnavailable,
  AgentClientError,
} from "./client.js";
import { startSleepWatch } from "./sleep-watch.js";
import {
  emptyVault,
  loadVault,
  encryptVault,
  writeEncryptedVaultFile,
} from "../core/vault.js";
import { VaultLockedError } from "../platform/keystore-passphrase.js";
import { setDefaultKdfForTests, writeMasterKeyFile } from "../platform/master-key-file.js";
import { resetSessionForTests, unlockSession } from "../platform/session.js";
import { resetUnlockAttempts, loadUnlockAttempts } from "../platform/unlock-attempts.js";
import { resetPlatformForTests } from "../platform/index.js";
import { setOpenTtyForTests, type TtyHandles } from "../core/prompt.js";
import { cmdUnlock } from "../commands/unlock.js";
import { PassphraseAuth } from "../platform/auth-passphrase.js";

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

function fakeTty(answer: string): () => TtyHandles {
  return () => {
    const input = new EventEmitter() as TtyHandles["input"];
    input.isTTY = true;
    input.setRawMode = () => undefined;
    input.resume = () => undefined;
    input.pause = () => undefined;
    const output = {
      write: () => true,
    } as TtyHandles["output"];
    queueMicrotask(() => {
      for (const ch of answer) {
        input.emit("keypress", ch, {});
      }
      input.emit("keypress", "", { name: "return" });
    });
    return {
      input,
      output,
      close: () => undefined,
    };
  };
}

describe.skipIf(process.platform === "win32")("abra agent passphrase-file", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";
  let socketPath = "";
  let vaultPath = "";
  let masterKey: Buffer;
  const PASS = "test-passphrase-12";

  beforeEach(async () => {
    await stopAgent();
    resetSessionForTests();
    resetUnlockAttempts();
    setDefaultKdfForTests({ N: 16384 });
    tmpDir = mkAgentTestDir();
    socketPath = path.join(tmpDir, "agent.sock");
    vaultPath = path.join(tmpDir, "vault.enc");
    masterKey = makeKey();
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_AGENT = "1";
    process.env.ABRA_AGENT_SOCKET = socketPath;
    process.env.ABRA_KEYSTORE = "passphrase-file";
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    resetPlatformForTests();
  });

  afterEach(async () => {
    await stopAgent();
    setOpenTtyForTests(null);
    setDefaultKdfForTests(null);
    resetSessionForTests();
    process.env = { ...envBackup };
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("fresh AgentState / startAgent starts locked; no key file written", async () => {
    const state = new AgentState({
      idleSeconds: 60,
      resolveMasterKey: async () => {
        throw new Error("should not resolve");
      },
    });
    expect(state.isLocked()).toBe(true);

    const { state: agentState } = await startAgent({
      socketPath,
      vaultPath: () => vaultPath,
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
      resolveMasterKey: async () => {
        throw new Error("should not resolve on start");
      },
    });
    expect(agentState.isLocked()).toBe(true);
    const st = await agentStatus({ socketPath });
    expect(st.locked).toBe(true);
    expect(st.maxAgeRemainingMs).toBeNull();

    // No accidental key persistence under ABRA_DIR or socket dir.
    const names = fs.readdirSync(tmpDir);
    expect(names.every((n) => !/key|master/i.test(n) || n === "agent.sock")).toBe(
      true,
    );
    expect(fs.existsSync(path.join(tmpDir, "master.key"))).toBe(false);
    expect(fs.existsSync(path.join(tmpDir, "agent.key"))).toBe(false);
  });

  it("unlock.key allowed peer → unlocked; vault.load works; status has no key", async () => {
    writeEncryptedVaultFile(encryptVault(emptyVault(), masterKey), vaultPath);
    const { state } = await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });

    await agentUnlockKey(masterKey, {
      socketPath,
      binding: {
        vaultPath: path.resolve(vaultPath),
        keystoreBackend: "passphrase-file",
      },
    });
    expect(state.isLocked()).toBe(false);

    const vault = emptyVault();
    vault.projects.p = {
      createdAt: 1,
      vars: { S: { value: "secret", secret: true, updatedAt: 1 } },
    };
    const { agentVaultSave } = await import("./client.js");
    await agentVaultSave(vault, { socketPath });
    const loaded = await agentVaultLoad({ socketPath });
    expect("vault" in loaded && loaded.vault.projects.p.vars.S.value).toBe("secret");

    const st = await agentStatus({ socketPath });
    expect(st.locked).toBe(false);
    const dump = JSON.stringify(st);
    expect(dump).not.toContain(masterKey.toString("base64"));
    expect(st).not.toHaveProperty("key");
  });

  it("unlock.key denied peer → forbidden_peer; agent stays locked", async () => {
    const { state } = await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: denyPeer,
      sleepWatch: false,
    });
    await expect(
      agentUnlockKey(masterKey, {
        socketPath,
        binding: {
          vaultPath: path.resolve(vaultPath),
          keystoreBackend: "passphrase-file",
        },
      }),
    ).rejects.toMatchObject({ code: "forbidden_peer" });
    expect(state.isLocked()).toBe(true);
  });

  it("unlock.key wrong keystore binding → mismatch", async () => {
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    await expect(
      agentUnlockKey(masterKey, {
        socketPath,
        binding: {
          vaultPath: path.resolve(vaultPath),
          keystoreBackend: "keytar",
        },
      }),
    ).rejects.toMatchObject({ code: "mismatch" });
  });

  it("unlock.key wrong-length / garbage → bad_request", async () => {
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    const short = Buffer.alloc(16).toString("base64");
    const res = await agentRequest(
      {
        op: "unlock.key",
        key: short,
        vaultPath: path.resolve(vaultPath),
        keystoreBackend: "passphrase-file",
      },
      { socketPath },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("bad_request");

    const garbage = await agentRequest(
      {
        op: "unlock.key",
        key: "!!!not-base64!!!",
        vaultPath: path.resolve(vaultPath),
        keystoreBackend: "passphrase-file",
      },
      { socketPath },
    );
    expect(garbage.ok).toBe(false);
    if (!garbage.ok) expect(garbage.code).toBe("bad_request");
  });

  it("unlock.key that does not decrypt vault.enc → rejected; still locked", async () => {
    writeEncryptedVaultFile(encryptVault(emptyVault(), masterKey), vaultPath);
    const { state } = await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    const wrong = makeKey();
    await expect(
      agentUnlockKey(wrong, {
        socketPath,
        binding: {
          vaultPath: path.resolve(vaultPath),
          keystoreBackend: "passphrase-file",
        },
      }),
    ).rejects.toMatchObject({
      code: "bad_request",
      message: expect.stringMatching(/does not decrypt vault/),
    });
    expect(state.isLocked()).toBe(true);
  });

  it("passphrase-file locked: unlock op returns locked; loadVault falls back", async () => {
    let resolveCalled = 0;
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
      resolveMasterKey: async () => {
        resolveCalled += 1;
        return masterKey;
      },
    });

    await expect(agentUnlock({ socketPath })).rejects.toMatchObject({
      code: "locked",
      message: expect.stringMatching(/abra unlock/),
    });
    expect(resolveCalled).toBe(0);

    expect(
      isAgentUnavailable(new AgentClientError("agent locked", "locked")),
    ).toBe(true);

    // Existing locked vault (no session) → VaultLockedError from direct path.
    writeMasterKeyFile(masterKey, PASS);
    resetSessionForTests();
    await expect(loadVault()).rejects.toBeInstanceOf(VaultLockedError);
    await expect(loadVault()).rejects.toThrow(/abra unlock/);
  });

  it("max age: activity does not extend; locks at deadline; clamp >8h", async () => {
    expect(resolveMaxAgeSeconds()).toBe(DEFAULT_MAX_AGE_SECONDS);
    process.env.ABRA_AGENT_MAX_AGE_SECONDS = String(9 * 60 * 60);
    expect(resolveMaxAgeSeconds()).toBe(DEFAULT_MAX_AGE_SECONDS);
    process.env.ABRA_AGENT_MAX_AGE_SECONDS = "not-a-number";
    expect(resolveMaxAgeSeconds()).toBe(DEFAULT_MAX_AGE_SECONDS);
    process.env.ABRA_AGENT_MAX_AGE_SECONDS = "3600";
    expect(resolveMaxAgeSeconds()).toBe(3600);

    vi.useFakeTimers({ shouldAdvanceTime: false });
    const key = makeKey();
    const state = new AgentState({
      idleSeconds: 24 * 60 * 60, // long idle so only max-age fires
      maxAgeSeconds: 8 * 60 * 60,
      resolveMasterKey: async () => key,
    });
    await state.unlock();
    const st0 = state.status();
    expect(st0.locked).toBe(false);
    expect(st0.maxAgeRemainingMs).toBeTypeOf("number");
    expect(st0.maxAgeRemainingMs!).toBeGreaterThan(7 * 60 * 60 * 1000);

    // Activity must not extend max age.
    await vi.advanceTimersByTimeAsync(4 * 60 * 60 * 1000);
    state.touch();
    const mid = state.status();
    expect(mid.maxAgeRemainingMs!).toBeLessThanOrEqual(4 * 60 * 60 * 1000 + 1000);

    await vi.advanceTimersByTimeAsync(4 * 60 * 60 * 1000 + 100);
    expect(state.isLocked()).toBe(true);
    expect(state.status().maxAgeRemainingMs).toBeNull();
  });

  it("idle lock still works alongside max age", async () => {
    vi.useFakeTimers();
    const key = makeKey();
    const state = new AgentState({
      idleSeconds: 2,
      maxAgeSeconds: 8 * 60 * 60,
      resolveMasterKey: async () => key,
    });
    await state.unlock();
    await vi.advanceTimersByTimeAsync(2100);
    expect(state.isLocked()).toBe(true);
  });

  it("lock zero-fills the buffer (kept reference)", async () => {
    const key = makeKey();
    const { state } = await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    await agentUnlockKey(key, {
      socketPath,
      binding: {
        vaultPath: path.resolve(vaultPath),
        keystoreBackend: "passphrase-file",
      },
    });
    const view = state.getKeyBufferForTests()!;
    expect(view.every((b) => b !== 0) || view.some((b) => b !== 0)).toBe(true);
    await agentLock({ socketPath });
    expect(view.every((b) => b === 0)).toBe(true);
  });

  it("cmdUnlock passphrase backend: one prompt, pushes unlock.key", async () => {
    writeMasterKeyFile(masterKey, PASS);
    writeEncryptedVaultFile(encryptVault(emptyVault(), masterKey), vaultPath);
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });

    let prompts = 0;
    setOpenTtyForTests(() => {
      prompts += 1;
      return fakeTty(PASS)();
    });

    const logs: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((m: unknown) => {
      logs.push(String(m));
    });
    await cmdUnlock();
    spy.mockRestore();

    expect(prompts).toBe(1);
    expect(logs.some((l) => l.includes("abra-agent holds the key"))).toBe(true);

    const st = await agentStatus({ socketPath });
    expect(st.locked).toBe(false);
  });

  it("cmdUnlock wrong passphrase → counter incremented, nothing pushed", async () => {
    writeMasterKeyFile(masterKey, PASS);
    const { state } = await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    setOpenTtyForTests(fakeTty("wrong-passphrase-xx"));
    await expect(cmdUnlock()).rejects.toThrow();
    expect(loadUnlockAttempts().failures).toBeGreaterThanOrEqual(1);
    expect(state.isLocked()).toBe(true);
  });

  it("cmdUnlock no agent → this process only message", async () => {
    writeMasterKeyFile(masterKey, PASS);
    process.env.ABRA_AGENT_SOCKET = path.join(tmpDir, "missing.sock");
    setOpenTtyForTests(fakeTty(PASS));
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((m: unknown) => {
      logs.push(String(m));
    });
    await cmdUnlock();
    expect(logs.some((l) => l.includes("this process only"))).toBe(true);
  });

  it("cmdUnlock agent forbidden_peer → warning, exit ok", async () => {
    writeMasterKeyFile(masterKey, PASS);
    writeEncryptedVaultFile(encryptVault(emptyVault(), masterKey), vaultPath);
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: denyPeer,
      sleepWatch: false,
    });
    setOpenTtyForTests(fakeTty(PASS));
    const errs: string[] = [];
    const logs: string[] = [];
    vi.spyOn(console, "error").mockImplementation((m: unknown) => {
      errs.push(String(m));
    });
    vi.spyOn(console, "log").mockImplementation((m: unknown) => {
      logs.push(String(m));
    });
    await cmdUnlock();
    expect(errs.some((e) => e.includes("forbidden_peer"))).toBe(true);
    expect(logs.some((l) => l.includes("this process only"))).toBe(true);
  });

  it("cmdUnlock non-passphrase auth → authenticate before prompt", async () => {
    writeMasterKeyFile(masterKey, PASS);
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_AGENT = "0";
    resetPlatformForTests();

    const authMod = await import("../platform/index.js");
    const authSpy = vi
      .spyOn(authMod, "authenticate")
      .mockResolvedValue(undefined);

    let prompts = 0;
    setOpenTtyForTests(() => {
      prompts += 1;
      return fakeTty(PASS)();
    });
    await cmdUnlock();
    expect(authSpy).toHaveBeenCalledTimes(1);
    expect(prompts).toBe(1);
  });

  it("PassphraseAuth still prompts while agent unlocked", async () => {
    writeMasterKeyFile(masterKey, PASS);
    writeEncryptedVaultFile(encryptVault(emptyVault(), masterKey), vaultPath);
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    await agentUnlockKey(masterKey, {
      socketPath,
      binding: {
        vaultPath: path.resolve(vaultPath),
        keystoreBackend: "passphrase-file",
      },
    });
    unlockSession(masterKey);

    let prompts = 0;
    setOpenTtyForTests(() => {
      prompts += 1;
      return fakeTty(PASS)();
    });
    const auth = new PassphraseAuth();
    await auth.authenticate({ reason: "reveal SECRET" });
    expect(prompts).toBe(1);
  });

  it("loadVaultViaAgent with locked passphrase-file does not hang", async () => {
    await startAgent({
      socketPath,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "passphrase-file",
      authorizePeer: allowPeer,
      sleepWatch: false,
    });
    await expect(loadVaultViaAgent({ socketPath })).rejects.toMatchObject({
      code: "locked",
    });
  });
});

describe("sleep watch", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function makeFakeChild() {
    const stdout = new EventEmitter();
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      kill: ReturnType<typeof vi.fn>;
      removeAllListeners: EventEmitter["removeAllListeners"];
    };
    child.stdout = stdout;
    child.kill = vi.fn();
    return child;
  }

  it("gdbus PrepareForSleep (true,) → onSleep; (false,) → not", () => {
    const onSleep = vi.fn();
    const child = makeFakeChild();
    const handle = startSleepWatch({
      platform: "linux",
      existsSync: (p) => p === "/usr/bin/gdbus",
      spawn: () => child as never,
      onSleep,
      log: () => undefined,
    });
    child.stdout.emit(
      "data",
      "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true,)\n",
    );
    expect(onSleep).toHaveBeenCalledTimes(1);
    child.stdout.emit(
      "data",
      "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (false,)\n",
    );
    expect(onSleep).toHaveBeenCalledTimes(1);
    handle.stop();
    expect(child.kill).toHaveBeenCalled();
  });

  it("dbus-monitor two-line format → onSleep", () => {
    const onSleep = vi.fn();
    const child = makeFakeChild();
    const handle = startSleepWatch({
      platform: "linux",
      existsSync: (p) => p === "/usr/bin/dbus-monitor",
      spawn: () => child as never,
      onSleep,
      log: () => undefined,
    });
    child.stdout.emit(
      "data",
      "signal time=1.0 sender=:1.0 -> destination=(null) path=/org/freedesktop/login1; interface=org.freedesktop.login1.Manager; member=PrepareForSleep\n",
    );
    expect(onSleep).not.toHaveBeenCalled();
    child.stdout.emit("data", "   boolean true\n");
    expect(onSleep).toHaveBeenCalledTimes(1);
    handle.stop();
  });

  it("no binaries → no-op with one log", () => {
    const logs: string[] = [];
    const onSleep = vi.fn();
    startSleepWatch({
      platform: "linux",
      existsSync: () => false,
      spawn: () => {
        throw new Error("should not spawn");
      },
      onSleep,
      log: (m) => logs.push(m),
    });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toMatch(/sleep lock unavailable/);
    expect(onSleep).not.toHaveBeenCalled();
  });

  it("child exit → restart with backoff then give up", async () => {
    vi.useFakeTimers();
    const logs: string[] = [];
    const children: ReturnType<typeof makeFakeChild>[] = [];
    const spawn = vi.fn(() => {
      const c = makeFakeChild();
      children.push(c);
      return c as never;
    });
    startSleepWatch({
      platform: "linux",
      existsSync: (p) => p === "/usr/bin/gdbus",
      spawn,
      onSleep: () => undefined,
      log: (m) => logs.push(m),
    });
    expect(spawn).toHaveBeenCalledTimes(1);

    for (let i = 0; i < 5; i++) {
      children[i]!.emit("exit", 1);
      await vi.advanceTimersByTimeAsync(200_000);
    }
    expect(spawn).toHaveBeenCalledTimes(6); // initial + 5 restarts
    children[5]!.emit("exit", 1);
    await vi.advanceTimersByTimeAsync(200_000);
    expect(logs.some((l) => /giving up/.test(l))).toBe(true);
    // no further spawns after give-up
    expect(spawn).toHaveBeenCalledTimes(6);
  });

  it("integration: startAgent injected sleep → sleep event locks agent", async () => {
    if (process.platform === "win32") return;
    const tmpDir = mkAgentTestDir();
    const socketPath = path.join(tmpDir, "agent.sock");
    const envBackup = { ...process.env };
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_AGENT = "1";
    process.env.ABRA_AGENT_SOCKET = socketPath;
    process.env.ABRA_KEYSTORE = "keytar";

    let sleepCb: (() => void) | null = null;
    const key = makeKey();
    try {
      const { state } = await startAgent({
        socketPath,
        resolveMasterKey: async () => key,
        authorizePeer: allowPeer,
        sleepWatch: ({ onSleep }) => {
          sleepCb = onSleep;
          return { stop: () => undefined };
        },
      });
      await agentUnlock({ socketPath });
      expect(state.isLocked()).toBe(false);
      sleepCb!();
      expect(state.isLocked()).toBe(true);
    } finally {
      await stopAgent();
      process.env = { ...envBackup };
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
