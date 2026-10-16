import { describe, it, expect, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { VAULT_UNCHANGED, type Vault } from "../core/vault.js";
import { generateSyncIdentity } from "./identity.js";
import { sealForPeer, sealProjects } from "./envelope.js";
import { upsertAcceptRule } from "./accept.js";
import {
  SyncInbox,
  createInboxRequestHandler,
  INBOX_PATH,
  RateLimiter,
  type InboxListener,
} from "./inbox.js";
import {
  InboxFullError,
  InboxQueue,
  ReplayCache,
  anchorsFile,
  anchorsFromVault,
  readAnchors,
  syncAnchorsFromVault,
  syncInboxDir,
  writeAnchors,
} from "../core/sync-inbox-store.js";
import { detectTailscaleIPv4, isTailscaleIPv4, type ExecFileFn } from "./tailscale.js";
import { AgentInbox } from "../agent/inbox.js";
import { entry, makePair, peerRecord } from "../../test/fixtures/sync-vaults.js";

const NOW = 1_800_000_000_000;
const posix = process.platform !== "win32";
const dirs: string[] = [];

function tempBase(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "abra-inbox-"));
  dirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true, maxRetries: 3 });
});

function withInbox(v: Vault): Vault {
  return { ...v, syncInbox: { enabled: true, port: 0 } };
}

function harness(initial: Vault, opts: { locked?: boolean; mirror?: boolean } = {}) {
  const base = tempBase();
  const state = { vault: structuredClone(initial), locked: opts.locked ?? false, now: NOW };
  const saves: Vault[] = [];
  const logs: string[] = [];
  if (opts.mirror !== false) writeAnchors(base, anchorsFromVault(withInbox(initial)));
  const inbox = new SyncInbox({
    base,
    now: () => state.now,
    loadUnlockedVault: async () => (state.locked ? null : structuredClone(state.vault)),
    updateVault: async (mutator) => {
      if (state.locked) throw new Error("Agent is locked");
      const draft = structuredClone(state.vault);
      const out = await mutator(draft);
      if (out === VAULT_UNCHANGED) return draft;
      state.vault = structuredClone(out ?? draft);
      saves.push(state.vault);
      return state.vault;
    },
    log: (l) => logs.push(l),
  });
  return { base, state, saves, logs, inbox };
}

function autoAll(v: Vault, from = "*"): Vault {
  return upsertAcceptRule(v, { from, projects: "*", auto: true }).vault;
}

describe("SyncInbox.receive", () => {
  it("locked agent → queued, still sealed, 0600 file in a 0700 dir; response carries no vault data", async () => {
    const { source, receiver } = makePair();
    const h = harness(autoAll(receiver), { locked: true });
    const env = sealForPeer(source, "mini", ["app"], { now: NOW });
    const out = await h.inbox.receive(JSON.parse(JSON.stringify(env)), { remote: "100.64.0.9" });
    expect(out.response).toEqual({ status: "queued" });
    expect(out.httpStatus).toBe(202);
    expect(h.saves).toHaveLength(0);

    const file = path.join(syncInboxDir(h.base), "queue", env.bundleId);
    const raw = fs.readFileSync(file, "utf8");
    expect(raw).toContain(env.ct);
    expect(raw).not.toContain("a-from-source");
    expect(h.inbox.queue.read(env.bundleId)).toMatchObject({ verifiedWith: "mirror", remote: "100.64.0.9" });
    if (posix) {
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      expect(fs.statSync(path.dirname(file)).mode & 0o777).toBe(0o700);
      expect(fs.statSync(syncInboxDir(h.base)).mode & 0o777).toBe(0o700);
    }
    expect(h.logs.join("\n")).not.toContain("from-source");
  });

  it("locked without a trust mirror → rejected (not configured)", async () => {
    const { source, receiver } = makePair();
    const h = harness(receiver, { locked: true, mirror: false });
    const out = await h.inbox.receive(sealForPeer(source, "mini", ["app"], { now: NOW }));
    expect(out.response).toEqual({ status: "rejected", reason: "not-configured" });
    expect(h.inbox.queue.ids()).toEqual([]);
  });

  it("unlocked + auto rule → applied via mergeScopedProjects: adds, keeps local on conflict, never deletes", async () => {
    const { source, receiver, sourceId } = makePair();
    const h = harness(autoAll(receiver, sourceId.id));
    const env = sealForPeer(source, "mini", ["app", "other"], { now: NOW });
    const out = await h.inbox.receive(env);
    expect(out.response).toEqual({ status: "applied" });
    expect(out.httpStatus).toBe(200);
    expect(out.counts).toEqual([
      { project: "app", isNew: false, added: 1, keptLocal: 1 },
      { project: "other", isNew: true, added: 1, keptLocal: 0 },
    ]);
    const v = h.state.vault;
    expect(v.projects.app.vars).toEqual({
      A: source.projects.app.vars.A,
      B: entry("b-local"),
      LOCAL: entry("only-here"),
    });
    expect(v.projects.other).toEqual(source.projects.other);
    expect(v.syncIdentity).toEqual(receiver.syncIdentity);
    expect(v.syncPeers).toEqual(receiver.syncPeers);
    expect(h.inbox.queue.ids()).toEqual([]);

    const again = await h.inbox.receive(env);
    expect(again.response).toEqual({ status: "rejected", reason: "replay" });
    expect(h.saves).toHaveLength(1);
  });

  it("unlocked without a matching auto rule → queued (verified against the vault)", async () => {
    const { source, receiver, sourceId } = makePair();
    const policy = upsertAcceptRule(receiver, { from: sourceId.id, projects: ["other"], auto: true }).vault;
    const h = harness(policy);
    const env = sealForPeer(source, "mini", ["app"], { now: NOW });
    expect((await h.inbox.receive(env)).response).toEqual({ status: "queued" });
    expect(h.saves).toHaveLength(0);
    expect(h.inbox.queue.read(env.bundleId).verifiedWith).toBe("vault");
    expect((await h.inbox.receive(env)).response).toEqual({ status: "rejected", reason: "replay" });
  });

  it.each([
    ["unknown sender", "unauthorized"],
    ["sender paired as receiver", "unauthorized"],
    ["bad signature", "unauthorized"],
    ["wrong recipient", "unauthorized"],
    ["stale", "stale"],
    ["malformed", "bad-request"],
  ])("rejects %s (locked and unlocked) without queueing or saving", async (kind, reason) => {
    for (const locked of [false, true]) {
      const { source, receiver, sourceId, receiverId } = makePair();
      let local = autoAll(receiver);
      let env: unknown = sealForPeer(source, "mini", ["app"], { now: NOW });
      if (kind === "unknown sender") {
        env = sealProjects(generateSyncIdentity(), { id: receiverId.id, x25519: receiverId.x25519.publicKey }, {
          app: source.projects.app,
        }, { now: NOW });
      } else if (kind === "sender paired as receiver") {
        local = { ...local, syncPeers: { [sourceId.id]: peerRecord(sourceId, "mbp", "receiver") } };
      } else if (kind === "bad signature") {
        const e = env as { sig: string };
        const sig = Buffer.from(e.sig, "base64");
        sig[0] ^= 1;
        env = { ...e, sig: sig.toString("base64") };
      } else if (kind === "wrong recipient") {
        const other = generateSyncIdentity();
        env = sealProjects(sourceId, { id: other.id, x25519: other.x25519.publicKey }, { app: source.projects.app }, { now: NOW });
      } else if (kind === "stale") {
        env = sealForPeer(source, "mini", ["app"], { now: NOW - 11 * 60_000 });
      } else if (kind === "malformed") {
        env = { hello: "world" };
      }
      const h = harness(local, { locked });
      const out = await h.inbox.receive(env, { remote: "10.0.0.1" });
      expect(out.response).toEqual({ status: "rejected", reason });
      expect(h.inbox.queue.ids()).toEqual([]);
      expect(h.saves).toHaveLength(0);
      expect(h.logs.some((l) => l.startsWith("rejected reason="))).toBe(true);
    }
  });

  it("processQueue on unlock applies only auto-matching bundles", async () => {
    const { source, receiver, sourceId } = makePair();
    const policy = upsertAcceptRule(receiver, { from: sourceId.id, projects: ["other"], auto: true }).vault;
    const h = harness(policy, { locked: true });
    const forOther = sealForPeer(source, "mini", ["other"], { now: NOW });
    const forApp = sealForPeer(source, "mini", ["app"], { now: NOW });
    await h.inbox.receive(forOther);
    await h.inbox.receive(forApp);
    expect(h.inbox.queue.ids().sort()).toEqual([forOther.bundleId, forApp.bundleId].sort());

    h.state.locked = false;
    h.state.now = NOW + 6 * 3_600_000; // hours later: queued bundles are not "stale"
    expect(await h.inbox.processQueue()).toEqual({ applied: 1, remaining: 1 });
    expect(h.state.vault.projects.other).toEqual(source.projects.other);
    expect(h.state.vault.projects.app.vars.A).toBeUndefined();
    expect(h.inbox.queue.ids()).toEqual([forApp.bundleId]);
  });

  it("an unpaired source's queued bundle is not applied later", async () => {
    const { source, receiver } = makePair();
    const h = harness(autoAll(receiver), { locked: true });
    await h.inbox.receive(sealForPeer(source, "mini", ["app"], { now: NOW }));
    h.state.vault = { ...h.state.vault, syncPeers: {} };
    h.state.locked = false;
    expect(await h.inbox.processQueue()).toEqual({ applied: 0, remaining: 1 });
    expect(h.saves).toHaveLength(0);
  });
});

describe("inbox store", () => {
  it("queue is bounded by count and bytes", () => {
    const { source } = makePair();
    const base = tempBase();
    const q = new InboxQueue(base, { maxCount: 1, maxBytes: 1024 * 1024 });
    const e1 = sealForPeer(source, "mini", ["app"]);
    q.write({ v: 1, receivedAt: 1, verifiedWith: "vault", envelope: e1 });
    expect(() => q.write({ v: 1, receivedAt: 1, verifiedWith: "vault", envelope: sealForPeer(source, "mini", ["app"]) }))
      .toThrow(InboxFullError);
    const tiny = new InboxQueue(tempBase(), { maxCount: 10, maxBytes: 100 });
    expect(() => tiny.write({ v: 1, receivedAt: 1, verifiedWith: "vault", envelope: e1 })).toThrow(InboxFullError);
    expect(() => q.read("../../etc/passwd")).toThrow(/invalid bundle id/);
  });

  it("replay cache prunes by age and caps entries", () => {
    const base = tempBase();
    const seen = new ReplayCache(base, { retentionMs: 1000, maxEntries: 2 });
    const ids = Array.from({ length: 3 }, () => crypto.randomUUID());
    seen.add(ids[0], NOW - 5000, NOW);
    expect(seen.has(ids[0])).toBe(false); // already outside retention
    seen.add(ids[0], NOW, NOW);
    seen.add(ids[1], NOW + 1, NOW);
    seen.add(ids[2], NOW + 2, NOW);
    expect([ids[0], ids[1], ids[2]].map((id) => seen.has(id))).toEqual([false, true, true]);
    if (posix) expect(fs.statSync(seen.file).mode & 0o777).toBe(0o600);
  });

  it("trust mirror holds only settings + source public keys and follows the vault", () => {
    const { receiver, sourceId } = makePair();
    const other = generateSyncIdentity();
    const v: Vault = {
      ...withInbox(receiver),
      syncPeers: { ...receiver.syncPeers, [other.id]: peerRecord(other, "pi", "receiver") },
    };
    const base = tempBase();
    syncAnchorsFromVault(base, v);
    const text = fs.readFileSync(anchorsFile(base), "utf8");
    expect(text).not.toContain("privateKey");
    expect(text).not.toContain(receiver.syncIdentity!.x25519.publicKey);
    expect(text).not.toContain(other.id);
    expect(readAnchors(base)).toEqual({
      v: 1,
      enabled: true,
      bind: null,
      port: 0,
      me: { id: receiver.syncIdentity!.id },
      sources: { [sourceId.id]: { name: "mbp", ed25519: sourceId.ed25519.publicKey } },
    });
    syncAnchorsFromVault(base, receiver); // inbox settings gone (e.g. restored vault)
    expect(fs.existsSync(anchorsFile(base))).toBe(false);
    fs.mkdirSync(syncInboxDir(base), { recursive: true });
    fs.writeFileSync(anchorsFile(base), "{nope");
    expect(readAnchors(base)).toBeNull();
  });
});

function request(
  port: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string | Buffer[] },
): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: opts.method ?? "POST", path: opts.path ?? INBOX_PATH, headers: opts.headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") }),
        );
      },
    );
    req.on("error", reject);
    if (Array.isArray(opts.body)) {
      for (const c of opts.body) req.write(c);
      req.end();
    } else req.end(opts.body);
  });
}

describe("inbox HTTP handler", () => {
  const servers: http.Server[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
  });

  async function serve(handler: http.RequestListener): Promise<number> {
    const server = http.createServer(handler);
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return (server.address() as AddressInfo).port;
  }

  it("POST JSON → service outcome; other paths/methods/types/sizes rejected", async () => {
    const { source, receiver } = makePair();
    const h = harness(receiver, { locked: true });
    const logs: string[] = [];
    const port = await serve(
      createInboxRequestHandler((raw, meta) => h.inbox.receive(raw, meta), {
        maxBodyBytes: 4096,
        rateLimit: { max: 100, windowMs: 60_000 },
        log: (l) => logs.push(l),
      }),
    );
    const json = { "Content-Type": "application/json" };
    const env = sealForPeer(source, "mini", ["app"], { now: NOW });

    const ok = await request(port, { headers: json, body: JSON.stringify(env) });
    expect(ok).toEqual({ status: 202, json: { status: "queued" } });

    expect(await request(port, { path: "/nope", headers: json, body: "{}" })).toEqual({
      status: 404,
      json: { status: "rejected", reason: "not-found" },
    });
    expect((await request(port, { method: "GET" })).status).toBe(405);
    expect((await request(port, { headers: { "Content-Type": "text/plain" }, body: "{}" })).json).toEqual({
      status: "rejected",
      reason: "unsupported-media-type",
    });
    expect((await request(port, { headers: { "Content-Type": "application/json; charset=utf-8" }, body: "{bad" })).json)
      .toEqual({ status: "rejected", reason: "bad-request" });
    const big = "x".repeat(5000);
    expect((await request(port, { headers: json, body: big })).status).toBe(413);
    expect((await request(port, { headers: json, body: [Buffer.from(big.slice(0, 2500)), Buffer.from(big.slice(2500))] })).status)
      .toBe(413);
    expect(logs.join("\n")).not.toContain(env.ct);
  });

  it("rate-limits per remote IP", async () => {
    const { receiver } = makePair();
    const h = harness(receiver, { locked: true });
    const port = await serve(
      createInboxRequestHandler((raw, meta) => h.inbox.receive(raw, meta), { rateLimit: { max: 2, windowMs: 60_000 } }),
    );
    const json = { "Content-Type": "application/json" };
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) statuses.push((await request(port, { headers: json, body: "{}" })).status);
    expect(statuses).toEqual([400, 400, 429]);
  });

  it("RateLimiter windows reset and the key table stays bounded", () => {
    const rl = new RateLimiter(1, 1000, 2);
    expect(rl.allow("a", 0)).toBe(true);
    expect(rl.allow("a", 10)).toBe(false);
    expect(rl.allow("a", 1000)).toBe(true);
    for (const k of ["b", "c", "d"]) rl.allow(k, 1001);
    expect((rl as unknown as { hits: Map<string, unknown> }).hits.size).toBeLessThanOrEqual(2);
  });
});

describe("tailscale detection (mocked)", () => {
  it("returns the CGNAT IPv4 from `tailscale ip -4`, trying candidates in order", async () => {
    const calls: { file: string; args: string[]; timeout: number }[] = [];
    const exec: ExecFileFn = async (file, args, opts) => {
      calls.push({ file, args, timeout: opts.timeout });
      if (file === "missing") throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      return { stdout: "100.101.102.103\n" };
    };
    expect(await detectTailscaleIPv4({ execFile: exec, candidates: ["missing", "tailscale"], timeoutMs: 1234 })).toBe(
      "100.101.102.103",
    );
    expect(calls).toEqual([
      { file: "missing", args: ["ip", "-4"], timeout: 1234 },
      { file: "tailscale", args: ["ip", "-4"], timeout: 1234 },
    ]);
  });

  it("null when unavailable or not a Tailscale address", async () => {
    expect(await detectTailscaleIPv4({ execFile: async () => ({ stdout: "192.168.1.5\n" }), candidates: ["t"] })).toBeNull();
    expect(
      await detectTailscaleIPv4({
        execFile: async () => {
          throw new Error("timed out");
        },
        candidates: ["t"],
      }),
    ).toBeNull();
    expect(isTailscaleIPv4("100.64.0.1")).toBe(true);
    expect(isTailscaleIPv4("100.128.0.1")).toBe(false);
    expect(isTailscaleIPv4("0.0.0.0")).toBe(false);
  });
});

describe("AgentInbox controller (listener lifecycle)", () => {
  function controller(base: string, vault: () => Vault | null, ts: string | null) {
    const started: { bind: string; port: number }[] = [];
    let open = 0;
    const logs: string[] = [];
    const c = new AgentInbox({
      base,
      loadUnlockedVault: async () => vault(),
      updateVault: async () => {
        throw new Error("unexpected vault write");
      },
      log: (l) => logs.push(l),
      detectTailscale: async () => ts,
      loadTls: () => ({ key: "k", cert: "c" }),
      startListener: async (o): Promise<InboxListener> => {
        started.push({ bind: o.bind, port: o.port });
        open += 1;
        return { bind: o.bind, port: o.port || 7333, close: async () => void (open -= 1) };
      },
    });
    return { c, started, logs, open: () => open };
  }

  it("does nothing without a trust mirror (inbox never enabled)", async () => {
    const base = tempBase();
    const { receiver } = makePair();
    const t = controller(base, () => receiver, "100.64.1.2");
    await t.c.start();
    await t.c.onUnlock();
    await t.c.onVaultSaved(receiver);
    expect(t.started).toEqual([]);
    expect(t.c.status()).toMatchObject({ configured: false, listening: false });
    expect(fs.existsSync(syncInboxDir(base))).toBe(false);
  });

  it("listens on the Tailscale IP when enabled with a source; follows disable / restore", async () => {
    const base = tempBase();
    const { receiver } = makePair();
    const enabled = { ...receiver, syncInbox: { enabled: true, port: 7333 } };
    writeAnchors(base, anchorsFromVault(enabled));
    const t = controller(base, () => enabled, "100.64.1.2");
    await t.c.start();
    expect(t.started).toEqual([{ bind: "100.64.1.2", port: 7333 }]);
    expect(t.c.status()).toMatchObject({ configured: true, enabled: true, listening: true, bind: "100.64.1.2", sources: 1 });

    await t.c.onVaultSaved({ ...enabled, syncInbox: { enabled: false, port: 7333 } });
    expect(t.open()).toBe(0);
    expect(t.c.status().listening).toBe(false);

    await t.c.onVaultSaved(enabled);
    expect(t.open()).toBe(1);
    await t.c.onVaultSaved(receiver); // inbox settings dropped (restore)
    expect(t.open()).toBe(0);
    expect(fs.existsSync(anchorsFile(base))).toBe(false);
    await t.c.stop();
  });

  it("refuses to start without Tailscale or an explicit bind; never falls back to 0.0.0.0", async () => {
    const base = tempBase();
    const { receiver } = makePair();
    writeAnchors(base, anchorsFromVault({ ...receiver, syncInbox: { enabled: true, port: 7333 } }));
    const t = controller(base, () => null, null);
    await t.c.start();
    expect(t.started).toEqual([]);
    expect(t.c.status()).toMatchObject({ listening: false, error: expect.stringMatching(/Tailscale/) });

    writeAnchors(base, anchorsFromVault({ ...receiver, syncInbox: { enabled: true, port: 7444, bind: "127.0.0.1" } }));
    const u = controller(base, () => null, null);
    await u.c.start();
    expect(u.started).toEqual([{ bind: "127.0.0.1", port: 7444 }]);
    await u.c.stop();
  });

  it("no source peers → no listener", async () => {
    const base = tempBase();
    const { receiver } = makePair();
    writeAnchors(base, anchorsFromVault({ ...receiver, syncPeers: {}, syncInbox: { enabled: true, port: 7333 } }));
    const t = controller(base, () => null, "100.64.1.2");
    await t.c.start();
    expect(t.started).toEqual([]);
  });

  it("onUnlock processes queued auto-matching bundles", async () => {
    const base = tempBase();
    const { source, receiver } = makePair();
    let vault: Vault = autoAll({ ...receiver, syncInbox: { enabled: true, port: 7333, bind: "127.0.0.1" } });
    writeAnchors(base, anchorsFromVault(vault));
    let locked = true;
    const c = new AgentInbox({
      base,
      loadUnlockedVault: async () => (locked ? null : structuredClone(vault)),
      updateVault: async (mutator) => {
        const draft = structuredClone(vault);
        const out = await mutator(draft);
        if (out !== VAULT_UNCHANGED) vault = out ?? draft;
        return vault;
      },
      log: () => {},
      loadTls: () => ({ key: "k", cert: "c" }),
      startListener: async (o) => ({ bind: o.bind, port: o.port, close: async () => {} }),
    });
    await c.start();
    const env = sealForPeer(source, "mini", ["other"]);
    expect((await c.inbox.receive(env)).response.status).toBe("queued");
    locked = false;
    await c.onUnlock();
    expect(vault.projects.other).toEqual(source.projects.other);
    expect(c.status().queued).toBe(0);
    await c.stop();
  });
});
