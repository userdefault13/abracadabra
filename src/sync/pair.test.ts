import { describe, it, expect, beforeAll, vi } from "vitest";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import type net from "node:net";
import tls from "node:tls";
import { VAULT_UNCHANGED, type Vault } from "../core/vault.js";
import { createEphemeralTls, type EphemeralTls } from "../core/tls-ephemeral.js";
import { NoTerminalError } from "../core/prompt.js";
import { generateSyncIdentity, getOrCreateSyncIdentity, identityFingerprint } from "./identity.js";
import {
  assertFullTlsFingerprint,
  LineChannel,
  pairConnect,
  pairListen,
  parsePairTarget,
  PAIR_APPROVAL_REASON,
  type PairDeps,
  type PairListenInfo,
  type PairResult,
} from "./pair.js";
import { PAIR_PROTOCOL, signTranscript } from "./sas.js";
import type { SyncPeerRole } from "../core/vault.js";

const hasOpenssl = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;
const PIN = "123456";

let sharedTls: EphemeralTls;

interface Side {
  deps: PairDeps;
  saves: Vault[];
  stored: () => Vault | null;
  lines: string[];
}

function side(host: string, opts: { confirm?: () => Promise<boolean>; pin?: string; initial?: Vault } = {}): Side {
  let stored: Vault | null = opts.initial ? structuredClone(opts.initial) : null;
  const saves: Vault[] = [];
  const lines: string[] = [];
  const load = async () => structuredClone(stored ?? { version: 1, projects: {}, connections: {} });
  const deps: PairDeps = {
    authenticate: vi.fn(async () => {}),
    loadVault: load,
    updateVault: vi.fn(async (mutator) => {
      const draft = await load();
      const out = await mutator(draft);
      if (out === VAULT_UNCHANGED) return draft;
      stored = structuredClone(out ?? draft);
      saves.push(structuredClone(stored));
      return structuredClone(stored);
    }),
    confirm: vi.fn(opts.confirm ?? (async () => true)),
    promptPin: vi.fn(async () => opts.pin ?? PIN),
    createTls: () => sharedTls,
    generatePin: () => PIN,
    hostname: () => host,
    now: () => 1_700_000_000_000,
    randomBytes: (n) => crypto.randomBytes(n),
    log: (l) => lines.push(l),
    timeouts: { stepMs: 5_000, confirmMs: 5_000, savedAckMs: 2_000, closeMs: 2_000 },
  };
  return { deps, saves, stored: () => stored, lines };
}

async function startListener(
  l: Side,
  opts: { role?: SyncPeerRole; name?: string; replace?: boolean; ttlMs?: number } = {},
): Promise<{ info: PairListenInfo; done: Promise<PairResult> }> {
  let onInfo!: (i: PairListenInfo) => void;
  const infoP = new Promise<PairListenInfo>((r) => (onInfo = r));
  const done = pairListen({ port: 0, bind: "127.0.0.1", ttlMs: opts.ttlMs ?? 30_000, ...opts, onListening: onInfo }, l.deps);
  done.catch(() => {}); // observed by the test
  const info = await Promise.race([infoP, done.then(() => Promise.reject(new Error("listener ended early")))]);
  return { info, done };
}

function connect(c: Side, info: PairListenInfo, opts: { role?: SyncPeerRole; name?: string; replace?: boolean; fingerprint?: string } = {}) {
  return pairConnect(
    { target: `127.0.0.1:${info.port}`, fingerprint: opts.fingerprint ?? info.tlsFingerprint, ...opts },
    c.deps,
  );
}

describe("pair target / fingerprint parsing", () => {
  it("parses host:port with the pairing default port", () => {
    expect(parsePairTarget("100.64.0.2")).toEqual({ host: "100.64.0.2", port: 7334 });
    expect(parsePairTarget("mini.tailnet.ts.net:9000")).toEqual({ host: "mini.tailnet.ts.net", port: 9000 });
    expect(parsePairTarget("[fd7a::1]:7400")).toEqual({ host: "fd7a::1", port: 7400 });
    expect(() => parsePairTarget("host:0")).toThrow(/invalid host:port/);
  });

  it("requires the full 64-hex TLS fingerprint (no legacy short prefix)", () => {
    expect(() => assertFullTlsFingerprint(undefined)).toThrow(/--fingerprint/);
    expect(() => assertFullTlsFingerprint("AA:BB:CC:DD:EE:FF:00:11")).toThrow(/full TLS fingerprint/);
    expect(assertFullTlsFingerprint("ab".repeat(32))).toBe("ab".repeat(32));
  });
});

/** Just enough of net.Socket for LineChannel, with events driven by the test. */
class FakeSocket extends EventEmitter {
  destroyed = false;
  writableEnded = false;
  setEncoding() {
    return this;
  }
  write() {
    return true;
  }
  end() {
    this.writableEnded = true;
    return this;
  }
  destroy() {
    if (!this.destroyed) {
      this.destroyed = true;
      this.emit("close");
    }
    return this;
  }
}

describe("LineChannel — peer closes right after its last frame", () => {
  const ack = `${JSON.stringify({ t: "saved", ok: true })}\n`;

  it("delivers the ack even when a reset and close arrive in the same tick", async () => {
    const sock = new FakeSocket();
    const ch = new LineChannel(sock as unknown as net.Socket, 50);
    const pending = ch.next(1_000, "the ack");
    sock.emit("data", ack);
    sock.emit("error", Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" }));
    sock.destroy();
    await expect(pending).resolves.toEqual({ t: "saved", ok: true });
  });

  it("frames received before end/close stay readable; only then does the close reason surface", async () => {
    const sock = new FakeSocket();
    const ch = new LineChannel(sock as unknown as net.Socket, 50);
    sock.emit("data", `${JSON.stringify({ t: "confirm", ok: true })}\n${ack}`);
    sock.emit("end");
    sock.destroy();
    await expect(ch.next(1_000, "confirm")).resolves.toMatchObject({ t: "confirm", ok: true });
    await expect(ch.next(1_000, "the ack")).resolves.toEqual({ t: "saved", ok: true });
    await expect(ch.next(1_000, "more")).rejects.toThrow(/peer disconnected/);
  });

  it("close() half-closes, then resolves only once the peer closes (or force-destroys after closeMs)", async () => {
    const sock = new FakeSocket();
    const ch = new LineChannel(sock as unknown as net.Socket, 60_000);
    let closed = false;
    const p = ch.close().then(() => (closed = true));
    expect(sock.writableEnded).toBe(true);
    expect(sock.destroyed).toBe(false);
    await new Promise((r) => setTimeout(r, 20));
    expect(closed).toBe(false);
    sock.destroy(); // peer's FIN → socket fully closed
    await p;
    expect(closed).toBe(true);

    const hung = new FakeSocket();
    await new LineChannel(hung as unknown as net.Socket, 20).close();
    expect(hung.destroyed).toBe(true);
  });
});

describe.skipIf(!hasOpenssl)("abra sync pair protocol (in-process)", () => {
  beforeAll(() => {
    sharedTls = createEphemeralTls("pair-test");
  });

  it("pairs both sides with complementary roles and the same safety code", async () => {
    const L = side("MacBook-Pro.local");
    const C = side("mac-mini");
    const { info, done } = await startListener(L);
    expect(info.role).toBe("source");
    expect(info.pin).toBe(PIN);
    const [lr, cr] = await Promise.all([done, connect(C, info)]);

    expect(L.deps.authenticate).toHaveBeenCalledWith(PAIR_APPROVAL_REASON);
    expect(C.deps.authenticate).toHaveBeenCalledWith(PAIR_APPROVAL_REASON);
    expect(lr.safetyCode).toEqual(cr.safetyCode);
    expect(lr.peerSaved && cr.peerSaved).toBe(true);
    expect(L.saves).toHaveLength(1);
    expect(C.saves).toHaveLength(1);

    const lv = L.stored()!;
    const cv = C.stored()!;
    expect(lv.syncPeers![cv.syncIdentity!.id]).toMatchObject({
      name: "mac-mini",
      role: "receiver",
      ed25519: cv.syncIdentity!.ed25519.publicKey,
      x25519: cv.syncIdentity!.x25519.publicKey,
      idFingerprint: identityFingerprint(cv.syncIdentity!.ed25519.publicKey, cv.syncIdentity!.x25519.publicKey),
      lastAddress: "127.0.0.1",
    });
    expect(cv.syncPeers![lv.syncIdentity!.id]).toMatchObject({
      name: "macbook-pro.local",
      role: "source",
      lastAddress: "127.0.0.1",
    });
    expect(info.identityFingerprint).toBe(
      identityFingerprint(lv.syncIdentity!.ed25519.publicKey, lv.syncIdentity!.x25519.publicKey),
    );

    // Output never shows private material.
    for (const [s, v] of [[L, lv], [C, cv]] as const) {
      const out = s.lines.join("\n");
      expect(out).not.toContain(v.syncIdentity!.ed25519.privateKey);
      expect(out).not.toContain(v.syncIdentity!.x25519.privateKey);
      expect(out).toContain(lr.safetyCode.words.join(" "));
    }
  });

  it("the listener settles only after the connector has read the ack and closed its side", async () => {
    const L = side("a");
    const C = side("b");
    const { info, done } = await startListener(L);
    let connectorEndedAt = 0;
    let listenerSettledAt = 0;
    const realConnect = tls.connect as (...args: unknown[]) => tls.TLSSocket;
    // A slow connector: its FIN goes out 300ms after it decides to close.
    const spy = vi.spyOn(tls, "connect").mockImplementation(((...args: unknown[]) => {
      const sock = realConnect(...args);
      const realEnd = sock.end.bind(sock) as () => tls.TLSSocket;
      sock.end = (() => {
        setTimeout(() => {
          connectorEndedAt ||= Date.now();
          realEnd();
        }, 300);
        return sock;
      }) as typeof sock.end;
      return sock;
    }) as typeof tls.connect);
    try {
      const [lr, cr] = await Promise.all([
        done.then((r) => {
          listenerSettledAt = Date.now();
          return r;
        }),
        connect(C, info),
      ]);
      expect(cr.peerSaved, cr.peerSaveError).toBe(true);
      expect(lr.peerSaved, lr.peerSaveError).toBe(true);
      expect(connectorEndedAt).toBeGreaterThan(0);
      expect(listenerSettledAt).toBeGreaterThanOrEqual(connectorEndedAt);
    } finally {
      spy.mockRestore();
    }
  });

  it("listener --role receiver makes the connector the source", async () => {
    const L = side("mini");
    const C = side("mbp");
    const { info, done } = await startListener(L, { role: "receiver" });
    const [lr, cr] = await Promise.all([done, connect(C, info, { role: "source" })]);
    expect(lr.myRole).toBe("receiver");
    expect(cr.myRole).toBe("source");
    expect(Object.values(L.stored()!.syncPeers!)[0].role).toBe("source");
    expect(Object.values(C.stored()!.syncPeers!)[0].role).toBe("receiver");
  });

  it("role collision aborts before any write", async () => {
    const L = side("a");
    const C = side("b");
    const { info, done } = await startListener(L, { role: "source" });
    const [lr, cr] = await Promise.allSettled([done, connect(C, info, { role: "source" })]);
    expect(lr.status).toBe("rejected");
    expect(cr.status === "rejected" && String(cr.reason)).toMatch(/role mismatch/);
    expect(L.saves).toHaveLength(0);
    expect(C.saves).toHaveLength(0);
    expect(C.deps.confirm).not.toHaveBeenCalled();
  });

  for (const decliner of ["listener", "connector"] as const) {
    it(`decline on the ${decliner} → neither vault written`, async () => {
      const no = async () => false;
      const L = side("a", decliner === "listener" ? { confirm: no } : {});
      const C = side("b", decliner === "connector" ? { confirm: no } : {});
      const { info, done } = await startListener(L);
      const [lr, cr] = await Promise.allSettled([done, connect(C, info)]);
      expect(lr.status).toBe("rejected");
      expect(cr.status).toBe("rejected");
      const declinerErr = decliner === "listener" ? lr : cr;
      const otherErr = decliner === "listener" ? cr : lr;
      expect(declinerErr.status === "rejected" && String(declinerErr.reason)).toMatch(/not confirmed on this machine/);
      expect(otherErr.status === "rejected" && String(otherErr.reason)).toMatch(/peer declined/);
      expect(L.saves).toHaveLength(0);
      expect(C.saves).toHaveLength(0);
    });
  }

  it("no TTY for the confirmation → abort, nothing written on either side", async () => {
    const L = side("a");
    const C = side("b", { confirm: async () => Promise.reject(new NoTerminalError()) });
    const { info, done } = await startListener(L);
    const [lr, cr] = await Promise.allSettled([done, connect(C, info)]);
    expect(cr.status === "rejected" && String(cr.reason)).toMatch(/could not confirm.*no terminal/);
    expect(lr.status).toBe("rejected");
    expect(L.saves).toHaveLength(0);
    expect(C.saves).toHaveLength(0);
  });

  it("locks after 8 bad PINs (listener closes; correct PIN no longer accepted)", async () => {
    const L = side("a");
    const { info, done } = await startListener(L);
    for (let i = 0; i < 8; i++) {
      const bad = side("b", { pin: "000000" });
      await expect(connect(bad, info)).rejects.toThrow(/invalid PIN/);
    }
    await expect(done).rejects.toThrow(/too many failed PIN attempts/);
    const good = side("b");
    await expect(connect(good, info)).rejects.toThrow();
    expect(L.saves).toHaveLength(0);
    expect(good.saves).toHaveLength(0);
  });

  it("TLS fingerprint mismatch → no bytes (no PIN) reach the server", async () => {
    const received: Buffer[] = [];
    const server = tls.createServer({ key: sharedTls.key, cert: sharedTls.cert }, (sock) => {
      sock.on("data", (d: Buffer) => received.push(d));
      sock.on("error", () => {});
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    try {
      const C = side("b");
      await expect(
        pairConnect({ target: `127.0.0.1:${port}`, fingerprint: "00".repeat(32) }, C.deps),
      ).rejects.toThrow(/fingerprint mismatch.*PIN not sent/);
      await new Promise((r) => setTimeout(r, 100));
      expect(Buffer.concat(received).length).toBe(0);
      expect(C.saves).toHaveLength(0);
    } finally {
      server.close();
    }
  });

  it("a listener presenting someone else's key (bad signature) is rejected", async () => {
    const victim = generateSyncIdentity();
    const mallory = generateSyncIdentity();
    const server = tls.createServer({ key: sharedTls.key, cert: sharedTls.cert }, (sock) => {
      sock.on("error", () => {});
      sock.once("data", () => {
        const hello = {
          protocol: PAIR_PROTOCOL,
          id: victim.id,
          name: "victim",
          ed25519: victim.ed25519.publicKey,
          x25519: victim.x25519.publicKey,
          nonce: crypto.randomBytes(32).toString("base64"),
          role: "source",
        };
        const sig = signTranscript(mallory, "listener", crypto.randomBytes(32));
        sock.write(`${JSON.stringify({ t: "hello", hello, sig })}\n`);
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    try {
      const C = side("b");
      await expect(
        pairConnect({ target: `127.0.0.1:${port}`, fingerprint: sharedTls.fingerprint }, C.deps),
      ).rejects.toThrow(/signature verification failed/);
      expect(C.deps.confirm).not.toHaveBeenCalled();
      expect(C.saves).toHaveLength(0);
    } finally {
      server.close();
    }
  });

  it("re-pairing the same machines updates in place; a new identity under a taken name needs --replace", async () => {
    const L = side("mbp");
    const C = side("mini");
    let s = await startListener(L);
    await Promise.all([s.done, connect(C, s.info)]);

    s = await startListener(L);
    const [lr, cr] = await Promise.all([s.done, connect(C, s.info)]);
    expect(lr.action).toBe("update");
    expect(cr.action).toBe("update");
    expect(Object.keys(L.stored()!.syncPeers!)).toHaveLength(1);

    // A different machine (fresh identity) also calling itself "mini".
    const impostor = side("mini");
    s = await startListener(L);
    const [lr2, ir] = await Promise.allSettled([s.done, connect(impostor, s.info)]);
    expect(lr2.status === "rejected" && String(lr2.reason)).toMatch(/already used by a different identity.*--replace/);
    expect(ir.status === "rejected" && String(ir.reason)).toMatch(/refused this pairing/);
    expect(impostor.saves).toHaveLength(0);
    expect(L.saves).toHaveLength(2);

    s = await startListener(L, { replace: true });
    const [lr3] = await Promise.all([s.done, connect(impostor, s.info)]);
    expect(lr3.action).toBe("replace");
    expect(Object.keys(L.stored()!.syncPeers!)).toEqual([impostor.stored()!.syncIdentity!.id]);
  });

  it("refuses a peer that presents this vault's own identity (cloned vault)", async () => {
    const shared = getOrCreateSyncIdentity({ version: 1, projects: {} }).vault;
    const L = side("a", { initial: shared });
    const C = side("b", { initial: shared });
    const { info, done } = await startListener(L);
    const [lr, cr] = await Promise.allSettled([done, connect(C, info)]);
    expect(lr.status === "rejected" && String(lr.reason)).toMatch(/own sync identity/);
    expect(cr.status).toBe("rejected");
    expect(L.saves).toHaveLength(0);
    expect(C.saves).toHaveLength(0);
  });

  it("approval happens before listening and a denied approval never listens", async () => {
    const L = side("a");
    vi.mocked(L.deps.authenticate).mockRejectedValueOnce(new Error("denied"));
    const onListening = vi.fn();
    await expect(pairListen({ port: 0, bind: "127.0.0.1", onListening }, L.deps)).rejects.toThrow(/denied/);
    expect(onListening).not.toHaveBeenCalled();

    const C = side("b");
    vi.mocked(C.deps.authenticate).mockRejectedValueOnce(new Error("denied"));
    await expect(
      pairConnect({ target: "127.0.0.1:1", fingerprint: "ab".repeat(32) }, C.deps),
    ).rejects.toThrow(/denied/);
    expect(C.deps.promptPin).not.toHaveBeenCalled();
  });

  it("listener TTL expiry closes without writing", async () => {
    const L = side("a");
    const { done } = await startListener(L, { ttlMs: 50 });
    await expect(done).rejects.toThrow(/expired/);
    expect(L.saves).toHaveLength(0);
  });
});
