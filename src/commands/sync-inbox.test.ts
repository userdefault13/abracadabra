import { describe, it, expect, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Vault } from "../core/vault.js";
import { sealForPeer } from "../sync/envelope.js";
import { SyncInbox } from "../sync/inbox.js";
import { ReplayCache, anchorsFile, readAnchors, syncInboxDir, writeAnchors, anchorsFromVault } from "../core/sync-inbox-store.js";
import { cmdSyncAccept, cmdSyncInbox, cmdSyncUnpair, defaultSyncDeps, type SyncDeps } from "./sync.js";
import { makePair } from "../../test/fixtures/sync-vaults.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true, maxRetries: 3 });
});

function memDeps(initial: Vault, opts: { tailscale?: string | null } = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "abra-cli-inbox-"));
  dirs.push(base);
  let stored = structuredClone(initial);
  const lines: string[] = [];
  const deps: SyncDeps = {
    ...defaultSyncDeps(),
    abraDir: () => base,
    authenticate: vi.fn(async () => {}),
    loadVault: async () => structuredClone(stored),
    saveVault: vi.fn(async (v: Vault) => {
      stored = structuredClone(v);
    }),
    confirm: vi.fn(async () => true),
    detectTailscale: vi.fn(async () => (opts.tailscale === undefined ? "100.64.7.8" : opts.tailscale)),
    agentInboxStatus: async () => null,
    log: (l) => lines.push(l),
  };
  return { deps, base, lines, stored: () => stored };
}

/** Queue envelopes the way a locked agent would. */
async function queueLocked(base: string, receiver: Vault, envs: unknown[]) {
  writeAnchors(base, anchorsFromVault({ ...receiver, syncInbox: { enabled: true, port: 0 } }));
  const inbox = new SyncInbox({ base, loadUnlockedVault: async () => null, saveVault: async () => {} });
  for (const e of envs) expect((await inbox.receive(e)).response.status).toBe("queued");
}

describe("abra sync accept", () => {
  it("adds/updates/removes rules after approval; --from must be a paired source", async () => {
    const { receiver, sourceId, receiverId } = makePair();
    const withReceiverPeer: Vault = {
      ...receiver,
      syncPeers: { ...receiver.syncPeers, [receiverId.id]: { ...receiver.syncPeers![sourceId.id], name: "pi", role: "receiver", ed25519: "x" } },
    };
    const m = memDeps(withReceiverPeer);

    await expect(cmdSyncAccept({ from: "pi", auto: true }, m.deps)).rejects.toThrow(/receiver for this machine/);
    await expect(cmdSyncAccept({ from: "ghost", auto: true }, m.deps)).rejects.toThrow(/no paired peer/);
    await expect(cmdSyncAccept({ projects: "__abra_treasury__" }, m.deps)).rejects.toThrow(/reserved/);
    expect(m.deps.authenticate).not.toHaveBeenCalled();

    await cmdSyncAccept({ from: "mbp", projects: "web,app", auto: true }, m.deps);
    await cmdSyncAccept({ auto: true }, m.deps);
    await cmdSyncAccept({ from: "mbp", projects: "app,web" }, m.deps); // same selector → update to queue
    expect(m.stored().syncAccept).toEqual([
      { from: sourceId.id, projects: ["app", "web"], auto: false },
      { from: "*", projects: "*", auto: true },
    ]);
    expect(m.deps.authenticate).toHaveBeenCalledTimes(3);

    m.lines.length = 0;
    await cmdSyncAccept({ list: true, json: true }, m.deps);
    expect(JSON.parse(m.lines.join("\n"))).toEqual([
      { from: sourceId.id, fromName: "mbp", projects: ["app", "web"], auto: false },
      { from: "*", fromName: null, projects: "*", auto: true },
    ]);

    await cmdSyncAccept({ remove: true }, m.deps);
    expect(m.stored().syncAccept).toHaveLength(1);
    await expect(cmdSyncAccept({ remove: true }, m.deps)).rejects.toThrow(/no accept rule/);
    await expect(cmdSyncAccept({ remove: true, auto: true }, m.deps)).rejects.toThrow(/cannot be combined/);
  });
});

describe("abra sync inbox --enable / --disable / --status", () => {
  it("--enable defaults to the Tailscale IP (stored as auto-detect) and writes the trust mirror", async () => {
    const { receiver, sourceId } = makePair();
    const m = memDeps(receiver);
    await cmdSyncInbox({ enable: true }, m.deps);
    expect(m.stored().syncInbox).toEqual({ enabled: true, port: 7333 });
    expect(m.lines.join("\n")).toContain("100.64.7.8");
    expect(readAnchors(m.base)).toMatchObject({ enabled: true, bind: null, port: 7333, sources: { [sourceId.id]: { name: "mbp" } } });

    await cmdSyncInbox({ disable: true }, m.deps);
    expect(m.stored().syncInbox).toEqual({ enabled: false, port: 7333 });
    expect(readAnchors(m.base)?.enabled).toBe(false);
    expect(m.deps.authenticate).toHaveBeenCalledTimes(2);
  });

  it("refuses to enable without Tailscale unless --bind is explicit (checked before approval)", async () => {
    const { receiver } = makePair();
    const m = memDeps(receiver, { tailscale: null });
    await expect(cmdSyncInbox({ enable: true }, m.deps)).rejects.toThrow(/Tailscale IPv4 not found/);
    expect(m.deps.authenticate).not.toHaveBeenCalled();
    await expect(cmdSyncInbox({ enable: true, bind: "nope" }, m.deps)).rejects.toThrow(/IP address/);
    await expect(cmdSyncInbox({ enable: true, port: "70000", bind: "127.0.0.1" }, m.deps)).rejects.toThrow(/--port/);
    await expect(cmdSyncInbox({ bind: "127.0.0.1" }, m.deps)).rejects.toThrow(/only apply with --enable/);
    await cmdSyncInbox({ enable: true, bind: "100.64.0.5", port: "7444" }, m.deps);
    expect(m.stored().syncInbox).toEqual({ enabled: true, bind: "100.64.0.5", port: 7444 });
  });

  it("--status --json reports settings + agent state, no vault data", async () => {
    const { receiver } = makePair();
    const m = memDeps({ ...receiver, syncInbox: { enabled: true, port: 7333 } });
    m.deps.agentInboxStatus = async () => ({
      configured: true,
      enabled: true,
      listening: true,
      bind: "100.64.7.8",
      port: 7333,
      sources: 1,
      queued: 0,
      error: null,
    });
    await cmdSyncInbox({ status: true, json: true }, m.deps);
    const out = JSON.parse(m.lines.join("\n"));
    expect(out).toEqual({
      enabled: true,
      bind: "tailscale",
      port: 7333,
      sources: 1,
      queued: 0,
      agent: true,
      listening: true,
      listeningOn: "100.64.7.8:7333",
      error: null,
    });
    expect(m.lines.join("\n")).not.toContain("only-here");
  });

  it("unpairing a source refreshes the trust mirror", async () => {
    const { receiver } = makePair();
    const m = memDeps({ ...receiver, syncInbox: { enabled: true, port: 7333 } });
    writeAnchors(m.base, anchorsFromVault(m.stored()));
    await cmdSyncUnpair("mbp", { yes: true }, m.deps);
    expect(readAnchors(m.base)?.sources).toEqual({});
  });
});

describe("abra sync inbox list / --apply / --reject", () => {
  it("lists queued bundles with verification status (JSON), without values", async () => {
    const { source, receiver, sourceId } = makePair();
    const m = memDeps(receiver);
    const env = sealForPeer(source, "mini", ["app"]);
    await queueLocked(m.base, receiver, [env]);
    await cmdSyncInbox({ json: true }, m.deps);
    const items = JSON.parse(m.lines.join("\n"));
    expect(items).toEqual([
      expect.objectContaining({ bundleId: env.bundleId, from: sourceId.id, fromName: "mbp", projects: ["app"], verified: true }),
    ]);
    expect(m.lines.join("\n")).not.toContain("from-source");
  });

  it("--apply merges receiver-wins, prints counts only, deletes the file, records the id", async () => {
    const { source, receiver } = makePair();
    const m = memDeps(receiver);
    const env = sealForPeer(source, "mini", ["app", "other"]);
    await queueLocked(m.base, receiver, [env]);

    await cmdSyncInbox({ apply: env.bundleId.toUpperCase() }, m.deps);
    expect(m.deps.authenticate).toHaveBeenCalledTimes(1);
    const v = m.stored();
    expect(v.projects.app.vars.A.value).toBe("a-from-source");
    expect(v.projects.app.vars.B.value).toBe("b-local");
    expect(v.projects.app.vars.LOCAL.value).toBe("only-here");
    expect(v.projects.other.vars.X.value).toBe("x-from-source");
    const out = m.lines.join("\n");
    expect(out).toContain("app: 1 added, 1 kept local");
    expect(out).toContain("other: new project, 1 added");
    expect(out).not.toMatch(/from-source|b-local|only-here/);
    expect(fs.readdirSync(path.join(syncInboxDir(m.base), "queue"))).toEqual([]);
    expect(new ReplayCache(m.base).has(env.bundleId)).toBe(true);
  });

  it("--apply all keeps bundles that no longer verify and fails non-zero", async () => {
    const { source, receiver } = makePair();
    const m = memDeps({ ...receiver, syncPeers: {} }); // source was unpaired after queueing
    const env = sealForPeer(source, "mini", ["app"]);
    await queueLocked(m.base, receiver, [env]);
    await expect(cmdSyncInbox({ apply: "all" }, m.deps)).rejects.toThrow(/could not be applied/);
    expect(m.deps.saveVault).not.toHaveBeenCalled();
    expect(m.lines.join("\n")).toContain("unknown-sender");
    expect(fs.existsSync(path.join(syncInboxDir(m.base), "queue", env.bundleId))).toBe(true);
  });

  it("--reject deletes without touching the vault; bad ids are refused", async () => {
    const { source, receiver } = makePair();
    const m = memDeps(receiver);
    const a = sealForPeer(source, "mini", ["app"]);
    const b = sealForPeer(source, "mini", ["other"]);
    await queueLocked(m.base, receiver, [a, b]);
    await expect(cmdSyncInbox({ reject: "../vault.enc" }, m.deps)).rejects.toThrow(/invalid bundle id/);
    await expect(cmdSyncInbox({ apply: a.bundleId, reject: "all" }, m.deps)).rejects.toThrow(/only one/);
    await cmdSyncInbox({ reject: "all" }, m.deps);
    expect(fs.readdirSync(path.join(syncInboxDir(m.base), "queue"))).toEqual([]);
    expect(m.deps.saveVault).not.toHaveBeenCalled();
    expect(fs.existsSync(anchorsFile(m.base))).toBe(true);
  });
});
