import { describe, it, expect, afterEach } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { loadVault } from "../core/vault.js";
import { vaultFile } from "../core/paths.js";
import { resetPlatformForTests } from "../platform/index.js";
import { setDefaultKdfForTests } from "../platform/master-key-file.js";
import { defaultSyncDeps } from "../commands/sync.js";
import { pairConnect } from "./pair.js";
import { identityFingerprint } from "./identity.js";

/**
 * Two real processes over loopback TLS: a child (tsx) runs the listener with its
 * own ABRA_DIR; this process is the connector with another ABRA_DIR. Requires
 * openssl on PATH (createEphemeralTls) — same assumption as the LAN tests.
 */

const hasOpenssl = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const HARNESS = path.join(ROOT, "test", "fixtures", "sync-pair-listener.ts");
const PASS = "loopback-test-passphrase"; // test-only headless vault passphrase

type Event =
  | { type: "listening"; port: number; pin: string; tlsFingerprint: string; identityFingerprint: string }
  | { type: "done"; ok: boolean; error?: string; safetyCode?: { words: string[]; digits: string }; peerId?: string };

function vaultEnv(dir: string): Record<string, string> {
  return {
    ABRA_DIR: dir,
    ABRA_KEYSTORE: "passphrase-file",
    ABRA_SKIP_BIOMETRICS: "1",
    ABRA_AUTH: "none",
    ABRA_HEADLESS_PASSPHRASE: PASS,
    ABRA_AGENT: "0",
  };
}

function useVaultEnv(dir: string) {
  Object.assign(process.env, vaultEnv(dir));
  resetPlatformForTests();
}

function startListenerChild(dir: string, answer: "yes" | "no") {
  const child = spawn(process.execPath, ["--import", "tsx", HARNESS, answer], {
    cwd: ROOT,
    env: { ...process.env, ...vaultEnv(dir) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr!.on("data", (d) => (stderr += String(d)));
  const events: Event[] = [];
  const waiters: ((e: Event) => void)[] = [];
  readline.createInterface({ input: child.stdout! }).on("line", (line) => {
    let ev: Event;
    try {
      ev = JSON.parse(line) as Event;
    } catch {
      return;
    }
    events.push(ev);
    waiters.splice(0).forEach((w) => w(ev));
  });
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  const next = (type: Event["type"]) =>
    new Promise<Event>((resolve, reject) => {
      const hit = events.find((e) => e.type === type);
      if (hit) return resolve(hit);
      const timer = setTimeout(() => reject(new Error(`harness: no ${type} event\n${stderr}`)), 45_000);
      const check = (e: Event) => {
        if (e.type === type) {
          clearTimeout(timer);
          resolve(e);
        } else waiters.push(check);
      };
      waiters.push(check);
      void exited.then(() => {
        setTimeout(() => {
          const late = events.find((e) => e.type === type);
          if (late) resolve(late);
          else reject(new Error(`harness exited before ${type}\n${stderr}`));
        }, 50);
      });
    });
  return { child, next, exited, stderr: () => stderr };
}

describe.skipIf(!hasOpenssl)("abra sync pair — loopback, two processes", () => {
  const envBackup = { ...process.env };
  const dirs: string[] = [];
  let child: ChildProcess | null = null;

  function tempDir(tag: string): string {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), `abra-${tag}-`));
    dirs.push(d);
    return d;
  }

  afterEach(() => {
    if (child && child.exitCode === null) child.kill();
    child = null;
    process.env = { ...envBackup };
    setDefaultKdfForTests(null);
    resetPlatformForTests();
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true, maxRetries: 3 });
  });

  async function connectFrom(dir: string, port: number, pin: string, fp: string, answer: boolean) {
    useVaultEnv(dir);
    setDefaultKdfForTests({ N: 16384 });
    return pairConnect(
      { target: `127.0.0.1:${port}`, fingerprint: fp },
      {
        ...defaultSyncDeps(),
        confirm: async () => answer,
        promptPin: async () => pin,
        log: () => {},
      },
    );
  }

  it("both vaults end up paired with complementary roles and the same safety code", async () => {
    const dirA = tempDir("la");
    const dirB = tempDir("lb");
    const h = startListenerChild(dirA, "yes");
    child = h.child;
    const listening = (await h.next("listening")) as Extract<Event, { type: "listening" }>;
    expect(listening.pin).toMatch(/^\d{6}$/);

    const result = await connectFrom(dirB, listening.port, listening.pin, listening.tlsFingerprint, true);
    const done = (await h.next("done")) as Extract<Event, { type: "done" }>;
    expect(done.ok, done.error).toBe(true);
    expect(await h.exited).toBe(0);
    expect(done.safetyCode).toEqual(result.safetyCode);
    expect(result.peerSaved).toBe(true);
    expect(result.myRole).toBe("receiver");

    const b = await loadVault(); // still dirB env
    useVaultEnv(dirA);
    const a = await loadVault();

    const aId = a.syncIdentity!;
    const bId = b.syncIdentity!;
    expect(identityFingerprint(aId.ed25519.publicKey, aId.x25519.publicKey)).toBe(listening.identityFingerprint);
    expect(a.syncPeers![bId.id]).toMatchObject({ role: "receiver", ed25519: bId.ed25519.publicKey, x25519: bId.x25519.publicKey });
    expect(b.syncPeers![aId.id]).toMatchObject({ role: "source", ed25519: aId.ed25519.publicKey, x25519: aId.x25519.publicKey });
    expect(done.peerId).toBe(bId.id);
    expect(Object.keys(a.projects)).toEqual([]);
    expect(Object.keys(b.projects)).toEqual([]);
  }, 60_000);

  it("a declined safety code on the listener writes neither vault", async () => {
    const dirA = tempDir("la");
    const dirB = tempDir("lb");
    const h = startListenerChild(dirA, "no");
    child = h.child;
    const listening = (await h.next("listening")) as Extract<Event, { type: "listening" }>;

    await expect(
      connectFrom(dirB, listening.port, listening.pin, listening.tlsFingerprint, true),
    ).rejects.toThrow(/peer declined/);
    const done = (await h.next("done")) as Extract<Event, { type: "done" }>;
    expect(done.ok).toBe(false);
    expect(done.error).toMatch(/not confirmed/);
    expect(await h.exited).toBe(1);

    expect(fs.existsSync(path.join(dirB, "vault.enc"))).toBe(false);
    expect(fs.existsSync(path.join(dirA, "vault.enc"))).toBe(false);
    useVaultEnv(dirB);
    expect(fs.existsSync(vaultFile())).toBe(false);
  }, 60_000);
});
