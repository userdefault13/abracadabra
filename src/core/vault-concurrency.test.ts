import { describe, it, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { readVaultFile, updateVaultFile, type Vault } from "./vault.js";
import { vaultFile } from "./paths.js";
import { acquireVaultLock, readVaultLock, releaseVaultLock, vaultLockPath } from "./vault-lock.js";
import { anchorsFromVault, writeAnchors } from "./sync-inbox-store.js";
import * as platform from "../platform/index.js";
import { setDefaultKdfForTests } from "../platform/master-key-file.js";
import { sealForPeer } from "../sync/envelope.js";
import { upsertAcceptRule } from "../sync/accept.js";
import { SyncInbox } from "../sync/inbox.js";
import { entry, makePair } from "../../test/fixtures/sync-vaults.js";
import { seedVault } from "../../test/fixtures/seed-vault.js";

/**
 * Real processes contending for one vault.enc (node --import tsx children, each
 * with the same temp ABRA_DIR and a test-only headless passphrase).
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const WRITER = path.join(ROOT, "test", "fixtures", "vault-writer.ts");
const HOLDER = path.join(ROOT, "test", "fixtures", "vault-lock-holder.ts");
const PASS = "concurrency-test-passphrase"; // test-only headless vault passphrase
const N = 3;
const M = 8;

const envBackup = { ...process.env };
const dirs: string[] = [];

afterEach(() => {
  process.env = { ...envBackup };
  setDefaultKdfForTests(null);
  platform.resetPlatformForTests();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true, maxRetries: 5 });
});

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

/** Temp vault dir with a passphrase-wrapped master key; this process is unlocked. */
async function setupVaultDir(): Promise<{ dir: string; key: Buffer; sync: string }> {
  // Short prefixes — Windows MAX_PATH is tight when nested under %TEMP%.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ac-"));
  const sync = fs.mkdtempSync(path.join(os.tmpdir(), "acs-"));
  dirs.push(dir, sync);
  Object.assign(process.env, vaultEnv(dir));
  setDefaultKdfForTests({ N: 16384 });
  platform.resetPlatformForTests();
  const key = crypto.randomBytes(32);
  await platform.restoreMasterKey(key, PASS);
  return { dir, key, sync };
}

function run(script: string, args: string[], dir: string) {
  const child = spawn(process.execPath, ["--import", "tsx", script, ...args], {
    cwd: ROOT,
    env: { ...process.env, ...vaultEnv(dir) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr!.on("data", (d) => (stderr += String(d)));
  const lines = readline.createInterface({ input: child.stdout! });
  const firstLine = new Promise<string>((resolve) => lines.once("line", resolve));
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  return { child, firstLine, exited, stderr: () => stderr };
}

async function waitFor(check: () => boolean, what: string, ms = 90_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

/** Start N writer processes, release them together, wait for all to exit 0. */
async function raceWriters(mode: "locked" | "naive", dir: string, sync: string, also?: () => Promise<void>) {
  const prefixes = Array.from({ length: N }, (_, i) => `W${i}`);
  const procs = prefixes.map((p) => run(WRITER, [mode, p, String(M), sync], dir));
  const dead = procs.map(() => false);
  procs.forEach((p, i) => void p.exited.then(() => (dead[i] = true)));
  await waitFor(() => {
    const early = dead.findIndex((d, i) => d && !fs.existsSync(path.join(sync, `ready-${prefixes[i]}`)));
    if (early >= 0) throw new Error(`writer ${prefixes[early]} exited before ready:\n${procs[early].stderr()}`);
    return prefixes.every((p) => fs.existsSync(path.join(sync, `ready-${p}`)));
  }, "writers ready");
  fs.writeFileSync(path.join(sync, "go"), "");
  await also?.();
  for (const p of procs) expect(await p.exited, p.stderr()).toBe(0);
  return prefixes;
}

function raceVarNames(v: Vault): string[] {
  return Object.keys(v.projects.race?.vars ?? {});
}

describe("vault write lock — multiple processes", () => {
  it(`${N} processes × ${M} updateVault calls: every write survives`, async () => {
    const { dir, key, sync } = await setupVaultDir();
    const prefixes = await raceWriters("locked", dir, sync);
    const names = raceVarNames(readVaultFile(vaultFile(), key)!);
    const expected = prefixes.flatMap((p) => Array.from({ length: M }, (_, i) => `${p}_${i}`));
    expect(names.sort()).toEqual(expected.sort());
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
    expect(fs.readdirSync(dir).filter((f) => /\.(tmp|stale)$/.test(f))).toEqual([]);
  }, 180_000);

  it("control: load outside the lock, save inside it — concurrent writers lose updates", async () => {
    const { key, dir, sync } = await setupVaultDir();
    await raceWriters("naive", dir, sync);
    const names = raceVarNames(readVaultFile(vaultFile(), key)!);
    expect(names.length).toBeGreaterThan(0);
    expect(names.length).toBeLessThan(N * M);
  }, 180_000);

  it("inbox auto-apply (abra-agent) racing CLI sets: neither side's changes are lost", async () => {
    const { dir, key, sync } = await setupVaultDir();
    const { source, receiver } = makePair();
    const receiverVault = upsertAcceptRule(
      { ...receiver, syncInbox: { enabled: true, port: 0 } },
      { from: "*", projects: "*", auto: true },
    ).vault;
    await seedVault(receiverVault);
    writeAnchors(dir, anchorsFromVault(receiverVault));

    // Same wiring abra-agent uses: in-memory key, locked read-modify-write of vault.enc.
    const inbox = new SyncInbox({
      base: dir,
      loadUnlockedVault: async () => readVaultFile(vaultFile(), key),
      updateVault: (mutator) => updateVaultFile(vaultFile(), () => key, mutator, { timeoutMs: 120_000 }),
    });
    const bundles = Array.from({ length: 6 }, (_, k) => {
      const project = `inbox${k}`;
      const src: Vault = { ...source, projects: { [project]: { createdAt: 1, vars: { [`K${k}`]: entry(`s${k}`) } } } };
      return { project, env: sealForPeer(src, "mini", [project]) };
    });

    const statuses: string[] = [];
    await raceWriters("locked", dir, sync, async () => {
      const outs = await Promise.all(bundles.map((b) => inbox.receive(JSON.parse(JSON.stringify(b.env)))));
      statuses.push(...outs.map((o) => o.response.status));
    });

    expect(statuses).toEqual(bundles.map(() => "applied"));
    const v = readVaultFile(vaultFile(), key)!;
    expect(raceVarNames(v)).toHaveLength(N * M);
    for (const [k, b] of bundles.entries()) expect(v.projects[b.project]?.vars[`K${k}`]?.value).toBe(`s${k}`);
    expect(v.projects.app.vars.LOCAL.value).toBe("only-here");
  }, 180_000);

  it("a holder that exits without releasing cleans up via the exit hook", async () => {
    const { dir } = await setupVaultDir();
    const h = run(HOLDER, [dir, "exit"], dir);
    expect(await h.firstLine).toBe("held");
    expect(await h.exited, h.stderr()).toBe(0);
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
  }, 60_000);

  it.skipIf(process.platform === "win32")(
    "a killed holder's lock is broken by the dead-pid check",
    async () => {
      const { dir } = await setupVaultDir();
      const h = run(HOLDER, [dir, "hang"], dir);
      expect(await h.firstLine).toBe("held");
      const pid = h.child.pid!;
      expect(readVaultLock(dir)?.pid).toBe(pid);
      h.child.kill("SIGKILL");
      await h.exited;
      expect(readVaultLock(dir)?.pid).toBe(pid); // no exit hook ran
      const got = await acquireVaultLock({ dir, timeoutMs: 10_000 });
      expect(got.pid).toBe(process.pid);
      releaseVaultLock(got.token, dir);
    },
    60_000,
  );
});
