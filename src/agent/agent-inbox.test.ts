import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { mkAgentTestDir } from "./paths.js";
import { startAgent, stopAgent, type AuthorizePeerFn } from "./server.js";
import { agentInboxStatus, agentUnlock, agentVaultSave } from "./client.js";
import { AgentInbox, type AgentInboxController } from "./inbox.js";
import { emptyVault, type Vault } from "../core/vault.js";
import { sealForPeer } from "../sync/envelope.js";
import { upsertAcceptRule } from "../sync/accept.js";
import { anchorsFromVault, writeAnchors } from "../core/sync-inbox-store.js";
import { makePair } from "../../test/fixtures/sync-vaults.js";

const allowPeer: AuthorizePeerFn = async () => ({ ok: true, pid: process.pid, exe: process.execPath });

describe.skipIf(process.platform === "win32")("abra agent ↔ sync inbox lifecycle", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";
  let socketPath = "";
  let vaultPath = "";
  const masterKey = crypto.randomBytes(32);

  beforeEach(async () => {
    await stopAgent();
    tmpDir = mkAgentTestDir();
    socketPath = path.join(tmpDir, "agent.sock");
    vaultPath = path.join(tmpDir, "vault.enc");
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_AGENT = "1";
    process.env.ABRA_AGENT_SOCKET = socketPath;
    process.env.ABRA_KEYSTORE = "keytar";
    process.env.ABRA_AUTH = "none";
  });

  afterEach(async () => {
    await stopAgent();
    process.env = { ...envBackup };
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function baseOpts() {
    return {
      socketPath,
      resolveMasterKey: async () => masterKey,
      vaultPath: () => vaultPath,
      authorizePeer: allowPeer,
      sleepWatch: false as const,
    };
  }

  it("default controller without an inbox config: no listener, status reports off", async () => {
    await startAgent(baseOpts());
    await agentUnlock({ socketPath });
    await agentVaultSave(emptyVault(), { socketPath });
    const st = await agentInboxStatus({ socketPath });
    expect(st).toMatchObject({ configured: false, enabled: false, listening: false, queued: 0 });
    expect(fs.existsSync(path.join(tmpDir, "sync-inbox"))).toBe(false);
  });

  it("start / unlock / vault.save / stop drive the controller", async () => {
    const calls: string[] = [];
    const fake: AgentInboxController = {
      start: vi.fn(async () => void calls.push("start")),
      onUnlock: vi.fn(async () => void calls.push("unlock")),
      onVaultSaved: vi.fn(async () => void calls.push("saved")),
      status: () => ({ configured: true, enabled: true, listening: true, bind: "100.64.0.1", port: 7333, sources: 1, queued: 2, error: null }),
      stop: vi.fn(async () => void calls.push("stop")),
    };
    await startAgent({ ...baseOpts(), syncInbox: () => fake });
    await agentUnlock({ socketPath });
    await agentVaultSave(emptyVault(), { socketPath });
    expect(await agentInboxStatus({ socketPath })).toMatchObject({ listening: true, queued: 2 });
    await stopAgent();
    expect(calls).toEqual(["start", "unlock", "saved", "stop"]);
  });

  it("queued-while-locked bundles are applied by the agent after unlock", async () => {
    const { source, receiver } = makePair();
    const local: Vault = upsertAcceptRule(
      { ...receiver, syncInbox: { enabled: true, port: 0, bind: "127.0.0.1" } },
      { from: "*", projects: "*", auto: true },
    ).vault;
    const { encryptVault, writeEncryptedVaultFile, decryptVault } = await import("../core/vault.js");
    writeEncryptedVaultFile(encryptVault(local, masterKey), vaultPath);
    writeAnchors(tmpDir, anchorsFromVault(local));

    let controller: AgentInbox | null = null;
    await startAgent({
      ...baseOpts(),
      syncInbox: (defaults) =>
        (controller = new AgentInbox({
          ...defaults,
          loadTls: () => ({ key: "k", cert: "c" }),
          startListener: async (o) => ({ bind: o.bind, port: 1, close: async () => {} }),
        })),
    });
    expect((await agentInboxStatus({ socketPath })).listening).toBe(true);
    const env = sealForPeer(source, "mini", ["other"]);
    expect((await controller!.inbox.receive(env)).response.status).toBe("queued");

    await agentUnlock({ socketPath });
    await vi.waitFor(async () => {
      const v = decryptVault(JSON.parse(fs.readFileSync(vaultPath, "utf8")), masterKey);
      expect(v.projects.other).toEqual(source.projects.other);
    });
    expect((await agentInboxStatus({ socketPath })).queued).toBe(0);
  });
});
