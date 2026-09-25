import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  mkAgentTestDir,
  ensureAgentRuntimeDir,
  isAgentEnabled,
} from "./paths.js";
import { AgentState } from "./state.js";
import {
  startAgent,
  stopAgent,
  getRunningAgentForTests,
} from "./server.js";
import {
  agentStatus,
  agentUnlock,
  agentLock,
  agentVaultLoad,
  agentVaultSave,
  agentRequest,
  loadVaultViaAgent,
  shouldTryAgent,
  isAgentUnavailable,
  AgentClientError,
} from "./client.js";
import { emptyVault, loadVault, saveVault, type Vault } from "../core/vault.js";
import { VaultLockedError } from "../platform/keystore-passphrase.js";

function makeKey(): Buffer {
  return crypto.randomBytes(32);
}

describe.skipIf(process.platform === "win32")("abra agent", () => {
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
    process.env.ABRA_KEYSTORE = "passphrase-file";
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

  it("status → unlock → vault.save/load round-trip; file mode 0600", async () => {
    const { state } = await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
    });

    const st0 = await agentStatus({ socketPath });
    expect(st0.locked).toBe(true);
    expect(st0.idleRemainingMs).toBeNull();
    expect(JSON.stringify(st0)).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/); // no key-like blobs

    await agentUnlock({ socketPath });
    const st1 = await agentStatus({ socketPath });
    expect(st1.locked).toBe(false);
    expect(st1.idleRemainingMs).toBeTypeOf("number");
    expect(Object.keys(st1).sort()).toEqual(["idleRemainingMs", "locked"]);

    const vault: Vault = emptyVault();
    vault.projects.demo = {
      createdAt: 1,
      vars: { TOKEN: { value: "secret-value", secret: true, updatedAt: 1 } },
    };
    await agentVaultSave(vault, { socketPath });
    expect(fs.existsSync(vaultPath)).toBe(true);
    expect(fs.statSync(vaultPath).mode & 0o777).toBe(0o600);

    const loaded = await agentVaultLoad({ socketPath });
    expect("vault" in loaded && loaded.vault).toBeTruthy();
    if ("vault" in loaded) {
      expect(loaded.vault.projects.demo.vars.TOKEN.value).toBe("secret-value");
    }

    // Internal key still present while unlocked
    expect(state.getKeyBufferForTests()?.equals(masterKey)).toBe(true);
  });

  it("lock zeroes the key buffer; vault ops fail until unlock", async () => {
    const { state } = await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
    });
    await agentUnlock({ socketPath });
    const buf = state.getKeyBufferForTests();
    expect(buf).not.toBeNull();
    const view = buf!;

    await agentLock({ socketPath });
    expect(state.isLocked()).toBe(true);
    expect(state.getKeyBufferForTests()).toBeNull();
    expect(view.every((b) => b === 0)).toBe(true);

    await expect(agentVaultLoad({ socketPath })).rejects.toMatchObject({
      code: "locked",
    });

    const st = await agentStatus({ socketPath });
    expect(st.locked).toBe(true);
    expect(JSON.stringify(st)).not.toContain(masterKey.toString("base64"));
  });

  it("idle timeout locks the agent", async () => {
    vi.useFakeTimers();
    const state = new AgentState({
      idleSeconds: 2,
      resolveMasterKey: async () => masterKey,
    });
    await state.unlock();
    expect(state.isLocked()).toBe(false);
    await vi.advanceTimersByTimeAsync(2100);
    expect(state.isLocked()).toBe(true);
    expect(state.getKeyBufferForTests()).toBeNull();
  });

  it("loadVault/saveVault fall back to direct keystore when agent disabled", async () => {
    process.env.ABRA_AGENT = "0";
    delete process.env.ABRA_AGENT_SOCKET;
    expect(isAgentEnabled()).toBe(false);
    expect(shouldTryAgent()).toBe(false);
  });

  it("loadVault falls back when no socket answers", async () => {
    const directDir = path.join(tmpDir, "direct");
    fs.mkdirSync(directDir, { mode: 0o700 });
    process.env.ABRA_DIR = directDir;
    process.env.ABRA_AGENT = "1";
    process.env.ABRA_AGENT_SOCKET = path.join(tmpDir, "missing.sock");
    process.env.ABRA_KEYSTORE = "passphrase-file";
    process.env.ABRA_HEADLESS_PASSPHRASE = "fallback-test-pass";

    const { writeMasterKeyFile } = await import("../platform/master-key-file.js");
    const { unlockSession } = await import("../platform/session.js");
    const { resetPlatformForTests } = await import("../platform/index.js");
    resetPlatformForTests();
    const key = makeKey();
    writeMasterKeyFile(key, "fallback-test-pass");
    unlockSession(key, "fallback-test-pass");

    const v = emptyVault();
    v.projects.fb = {
      createdAt: 1,
      vars: { K: { value: "v", secret: true, updatedAt: 1 } },
    };
    await saveVault(v);
    expect(fs.existsSync(path.join(directDir, "vault.enc"))).toBe(true);
    const loaded = await loadVault();
    expect(loaded.projects.fb.vars.K.value).toBe("v");
  });

  it("refuses runtime dir with group/other bits (0755)", () => {
    const bad = path.join(tmpDir, "badperm");
    fs.mkdirSync(bad, { mode: 0o755 });
    // Force mode in case umask stripped bits
    fs.chmodSync(bad, 0o755);
    expect(() => ensureAgentRuntimeDir(bad)).toThrow(/0700/);
  });

  it("refuses runtime dir with wrong owner", () => {
    const d = path.join(tmpDir, "owner");
    fs.mkdirSync(d, { mode: 0o700 });
    const realUid = process.getuid!();
    expect(() => ensureAgentRuntimeDir(d, realUid + 1)).toThrow(/owner mismatch/);
  });

  it("replaces a stale socket and refuses a second live agent", async () => {
    // Stale: create a non-listening socket file
    fs.writeFileSync(socketPath, "");
    const first = await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
    });
    expect(first.socketPath).toBe(socketPath);

    await expect(
      startAgent({
        socketPath,
        resolveMasterKey: async () => masterKey,
        vaultPath: () => vaultPath,
      }),
    ).rejects.toThrow(/already running/);

    // In-process guard
    expect(getRunningAgentForTests()).not.toBeNull();
  });

  it("loadVaultViaAgent auto-unlocks when locked", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
    });
    const vault = emptyVault();
    vault.projects.x = { createdAt: 1, vars: {} };
    // save via unlock+save path
    const loaded = await loadVaultViaAgent({ socketPath });
    expect(loaded.version).toBe(1);

    await agentLock({ socketPath });
    // empty file still ok after unlock
    const again = await loadVaultViaAgent({ socketPath });
    expect(again.version).toBe(1);
  });

  it("AgentState.lock zeroes without server", () => {
    const key = makeKey();
    const state = new AgentState({
      idleSeconds: 60,
      resolveMasterKey: async () => key,
    });
    return state.unlock().then(() => {
      const buf = state.getKeyBufferForTests()!;
      state.lock();
      expect(buf.every((b) => b === 0)).toBe(true);
      expect(state.status()).toEqual({ locked: true, idleRemainingMs: null });
    });
  });

  it("rejects oversized frames", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
    });
    await agentUnlock({ socketPath });
    // Status never includes key material:
    const res = await agentRequest({ op: "status" }, { socketPath });
    expect(res.ok).toBe(true);
    if (res.ok && res.op === "status") {
      expect(res.status).not.toHaveProperty("key");
      expect(res.status).not.toHaveProperty("masterKey");
    }
  });

  it("matching vault path + keystore round-trips via loadVault/saveVault", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => path.resolve(vaultPath),
    });
    const v = emptyVault();
    v.projects.round = {
      createdAt: 1,
      vars: { R: { value: "via-agent", secret: true, updatedAt: 1 } },
    };
    await saveVault(v);
    expect(fs.existsSync(vaultPath)).toBe(true);
    const loaded = await loadVault();
    expect(loaded.projects.round.vars.R.value).toBe("via-agent");
  });

  it("different ABRA_DIR → mismatch; client falls back; agent vault.enc unchanged", async () => {
    const agentDir = path.join(tmpDir, "ag");
    const clientDir = path.join(tmpDir, "cl");
    fs.mkdirSync(agentDir, { mode: 0o700 });
    fs.mkdirSync(clientDir, { mode: 0o700 });
    const agentVault = path.join(agentDir, "vault.enc");

    process.env.ABRA_DIR = agentDir;
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => agentVault,
    });
    await agentUnlock({ socketPath });
    const seed = emptyVault();
    seed.projects.agent = {
      createdAt: 1,
      vars: { A: { value: "agent-only", secret: true, updatedAt: 1 } },
    };
    await agentVaultSave(seed, { socketPath });
    const agentBytesBefore = fs.readFileSync(agentVault);

    process.env.ABRA_DIR = clientDir;
    process.env.ABRA_HEADLESS_PASSPHRASE = "fallback-mismatch-pass";
    const { writeMasterKeyFile } = await import("../platform/master-key-file.js");
    const { unlockSession } = await import("../platform/session.js");
    const { resetPlatformForTests } = await import("../platform/index.js");
    resetPlatformForTests();
    const clientKey = makeKey();
    writeMasterKeyFile(clientKey, "fallback-mismatch-pass");
    unlockSession(clientKey, "fallback-mismatch-pass");

    await expect(agentVaultLoad({ socketPath })).rejects.toMatchObject({
      code: "mismatch",
    });
    expect(
      isAgentUnavailable(new AgentClientError("vault path mismatch", "mismatch")),
    ).toBe(true);

    const v = emptyVault();
    v.projects.client = {
      createdAt: 1,
      vars: { C: { value: "client-v", secret: true, updatedAt: 1 } },
    };
    await saveVault(v);
    expect(fs.existsSync(path.join(clientDir, "vault.enc"))).toBe(true);
    expect(fs.readFileSync(agentVault).equals(agentBytesBefore)).toBe(true);

    const loaded = await loadVault();
    expect(loaded.projects.client.vars.C.value).toBe("client-v");
    expect(loaded.projects.agent).toBeUndefined();
  });

  it("keystore backend mismatch → mismatch (unavailable)", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => path.resolve(vaultPath),
      keystoreBackend: () => "keytar",
    });
    // Client env is passphrase-file
    await expect(agentVaultLoad({ socketPath })).rejects.toMatchObject({
      code: "mismatch",
    });
  });

  it("missing vaultPath in request → mismatch", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => path.resolve(vaultPath),
    });
    await agentUnlock({ socketPath });
    const res = await agentRequest({ op: "vault.load" }, { socketPath });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("mismatch");
  });

  it("unlock failure → unavailable; loadVault/saveVault fall back to direct path", async () => {
    await startAgent({
      socketPath,
      resolveMasterKey: async () => {
        throw new VaultLockedError();
      },
      vaultPath: () => path.resolve(vaultPath),
    });

    await expect(agentUnlock({ socketPath })).rejects.toMatchObject({
      code: "unavailable",
    });
    expect(
      isAgentUnavailable(new AgentClientError("locked vault", "unavailable")),
    ).toBe(true);

    process.env.ABRA_HEADLESS_PASSPHRASE = "unlock-fail-pass";
    const { writeMasterKeyFile } = await import("../platform/master-key-file.js");
    const { unlockSession } = await import("../platform/session.js");
    const { resetPlatformForTests } = await import("../platform/index.js");
    resetPlatformForTests();
    const key = makeKey();
    writeMasterKeyFile(key, "unlock-fail-pass");
    unlockSession(key, "unlock-fail-pass");

    const v = emptyVault();
    v.projects.fb = {
      createdAt: 1,
      vars: { K: { value: "direct-after-unlock-fail", secret: true, updatedAt: 1 } },
    };
    await saveVault(v);
    expect(fs.existsSync(vaultPath)).toBe(true);
    const loaded = await loadVault();
    expect(loaded.projects.fb.vars.K.value).toBe("direct-after-unlock-fail");
  });
});

describe("isAgentEnabled", () => {
  const envBackup = { ...process.env };
  const originalPlatform = process.platform;

  function setPlatform(platform: NodeJS.Platform): void {
    Object.defineProperty(process, "platform", {
      value: platform,
      configurable: true,
    });
  }

  afterEach(() => {
    process.env = { ...envBackup };
    Object.defineProperty(process, "platform", {
      value: originalPlatform,
      configurable: true,
    });
  });

  it("win32 default → false", () => {
    setPlatform("win32");
    delete process.env.ABRA_AGENT;
    delete process.env.XDG_RUNTIME_DIR;
    expect(isAgentEnabled()).toBe(false);
  });

  it("win32 with ABRA_AGENT=1 → false", () => {
    setPlatform("win32");
    process.env.ABRA_AGENT = "1";
    expect(isAgentEnabled()).toBe(false);
  });

  it("win32 with XDG_RUNTIME_DIR set → false", () => {
    setPlatform("win32");
    delete process.env.ABRA_AGENT;
    process.env.XDG_RUNTIME_DIR = "/run/user/1000";
    expect(isAgentEnabled()).toBe(false);
  });

  it("linux with XDG_RUNTIME_DIR → true", () => {
    setPlatform("linux");
    delete process.env.ABRA_AGENT;
    process.env.XDG_RUNTIME_DIR = "/run/user/1000";
    expect(isAgentEnabled()).toBe(true);
  });

  it("linux ABRA_AGENT=0 → false", () => {
    setPlatform("linux");
    process.env.ABRA_AGENT = "0";
    process.env.XDG_RUNTIME_DIR = "/run/user/1000";
    expect(isAgentEnabled()).toBe(false);
  });

  it("darwin default → false", () => {
    setPlatform("darwin");
    delete process.env.ABRA_AGENT;
    delete process.env.XDG_RUNTIME_DIR;
    expect(isAgentEnabled()).toBe(false);
  });

  it("darwin ABRA_AGENT=1 → true", () => {
    setPlatform("darwin");
    process.env.ABRA_AGENT = "1";
    expect(isAgentEnabled()).toBe(true);
  });
});
