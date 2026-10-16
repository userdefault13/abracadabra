import { describe, it, expect, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  VaultLockNotHeldError,
  VaultLockTimeoutError,
  acquireVaultLock,
  assertVaultLockHeld,
  currentVaultLockToken,
  defaultIsPidAlive,
  isVaultLockHeld,
  readVaultLock,
  releaseVaultLock,
  vaultLockPath,
  withVaultLock,
  type VaultLockInfo,
} from "./vault-lock.js";

const dirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true, maxRetries: 3 });
});

function tempDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "abra-lock-"));
  dirs.push(d);
  return d;
}

const HOST = os.hostname();
const OTHER_PID = 424_242;

function plant(dir: string, info: Partial<VaultLockInfo> & { pid: number }): VaultLockInfo {
  const full: VaultLockInfo = { hostname: HOST, createdAt: Date.now(), token: `planted-${Math.random()}`, ...info };
  fs.writeFileSync(vaultLockPath(dir), JSON.stringify(full));
  return full;
}

/** Fake clock whose sleep advances time — timeouts resolve instantly. */
function fakeClock(start = 1_000_000) {
  let t = start;
  return { now: () => t, sleep: async (ms: number) => void (t += ms) };
}

describe("acquire / release", () => {
  it("creates vault.lock exclusively with {pid, hostname, createdAt, token}; release removes it", async () => {
    const dir = tempDir();
    const info = await acquireVaultLock({ dir });
    expect(info).toMatchObject({ pid: process.pid, hostname: HOST });
    expect(info.token).toMatch(/^[0-9a-f]{32}$/);
    expect(readVaultLock(dir)).toEqual(info);
    if (process.platform !== "win32") expect(fs.statSync(vaultLockPath(dir)).mode & 0o777).toBe(0o600);

    expect(releaseVaultLock(info.token, dir)).toBe(true);
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]); // no stray .stale files
  });

  it("withVaultLock releases in finally, also when fn throws", async () => {
    const dir = tempDir();
    await expect(
      withVaultLock(() => {
        expect(fs.existsSync(vaultLockPath(dir))).toBe(true);
        throw new Error("boom");
      }, { dir }),
    ).rejects.toThrow("boom");
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
    expect(await withVaultLock(() => 7, { dir })).toBe(7);
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
  });

  it("release with a mismatched token is a no-op", async () => {
    const dir = tempDir();
    const info = await acquireVaultLock({ dir });
    expect(releaseVaultLock("not-the-token", dir)).toBe(false);
    expect(readVaultLock(dir)?.token).toBe(info.token);
    expect(releaseVaultLock(info.token, dir)).toBe(true);
    expect(releaseVaultLock(info.token, dir)).toBe(false); // already gone
  });

  it("a holder whose lock was replaced does not delete the new lock on release", async () => {
    const dir = tempDir();
    await withVaultLock(() => {
      plant(dir, { pid: OTHER_PID }); // someone broke ours and took it
    }, { dir });
    expect(readVaultLock(dir)?.pid).toBe(OTHER_PID);
  });
});

describe("waiting / timeout", () => {
  it("times out with VaultLockTimeoutError naming the holder pid and lock age", async () => {
    const dir = tempDir();
    const clock = fakeClock();
    plant(dir, { pid: OTHER_PID, createdAt: clock.now() - 2_500 });
    const err = await acquireVaultLock({ dir, timeoutMs: 1_000, isPidAlive: () => true, ...clock }).catch((e) => e);
    expect(err).toBeInstanceOf(VaultLockTimeoutError);
    expect(err.holder.pid).toBe(OTHER_PID);
    expect(err.ageMs).toBeGreaterThanOrEqual(3_500);
    expect(err.message).toContain(`pid ${OTHER_PID}`);
    expect(err.message).toMatch(/held for \d+\.\ds/);
    expect(readVaultLock(dir)?.pid).toBe(OTHER_PID); // untouched
  });

  it("waits with backoff and gets the lock once the holder releases", async () => {
    const dir = tempDir();
    const holder = await acquireVaultLock({ dir });
    let slept = 0;
    const p = acquireVaultLock({
      dir,
      sleep: async (ms) => {
        slept += 1;
        if (slept === 3) releaseVaultLock(holder.token, dir);
        await new Promise((r) => setTimeout(r, Math.min(ms, 5)));
      },
    });
    const got = await p;
    expect(got.token).not.toBe(holder.token);
    expect(slept).toBe(3);
    releaseVaultLock(got.token, dir);
  });

  it("does not break a live holder on another host, however young", async () => {
    const dir = tempDir();
    const clock = fakeClock();
    plant(dir, { pid: OTHER_PID, hostname: "some-other-mac", createdAt: clock.now() });
    await expect(
      acquireVaultLock({ dir, timeoutMs: 500, isPidAlive: () => false, ...clock }),
    ).rejects.toBeInstanceOf(VaultLockTimeoutError);
  });
});

describe("stale locks", () => {
  it("breaks a lock whose pid is dead on this host", async () => {
    const dir = tempDir();
    const dead = plant(dir, { pid: OTHER_PID });
    const got = await acquireVaultLock({ dir, timeoutMs: 1_000, isPidAlive: (pid) => pid !== OTHER_PID });
    expect(got.token).not.toBe(dead.token);
    expect(readVaultLock(dir)?.token).toBe(got.token);
    releaseVaultLock(got.token, dir);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it("treats EPERM from kill(pid, 0) as alive, ESRCH as dead", () => {
    const kill = vi.spyOn(process, "kill");
    kill.mockImplementation(() => {
      throw Object.assign(new Error("perm"), { code: "EPERM" });
    });
    expect(defaultIsPidAlive(OTHER_PID)).toBe(true);
    kill.mockImplementation(() => {
      throw Object.assign(new Error("gone"), { code: "ESRCH" });
    });
    expect(defaultIsPidAlive(OTHER_PID)).toBe(false);
    kill.mockImplementation(() => true);
    expect(defaultIsPidAlive(OTHER_PID)).toBe(true);
  });

  it("breaks a lock older than maxHoldMs even if its holder is alive", async () => {
    const dir = tempDir();
    const clock = fakeClock();
    plant(dir, { pid: OTHER_PID, createdAt: clock.now() - 31_000 });
    const got = await acquireVaultLock({ dir, isPidAlive: () => true, ...clock });
    expect(readVaultLock(dir)?.token).toBe(got.token);
    releaseVaultLock(got.token, dir);
  });

  it("respects a custom maxHoldMs and ages unparseable locks by mtime", async () => {
    const dir = tempDir();
    fs.writeFileSync(vaultLockPath(dir), "{garbage");
    const old = new Date(Date.now() - 5_000);
    fs.utimesSync(vaultLockPath(dir), old, old);
    await expect(
      acquireVaultLock({ dir, timeoutMs: 200, maxHoldMs: 60_000, sleep: async () => {} }),
    ).rejects.toThrow(/unknown process/);
    const got = await acquireVaultLock({ dir, maxHoldMs: 1_000 });
    expect(readVaultLock(dir)?.token).toBe(got.token);
    releaseVaultLock(got.token, dir);
  });

  it("our own pid with a token this process doesn't hold is a reused pid → stale", async () => {
    const dir = tempDir();
    plant(dir, { pid: process.pid });
    const got = await acquireVaultLock({ dir, timeoutMs: 1_000 });
    expect(readVaultLock(dir)?.token).toBe(got.token);
    releaseVaultLock(got.token, dir);
  });

  it("concurrent breakers: a breaker that lost the race puts the winner's fresh lock back", async () => {
    const dir = tempDir();
    const clock = fakeClock();
    const stale = plant(dir, { pid: OTHER_PID });
    const WINNER_PID = OTHER_PID + 1;
    let winner: VaultLockInfo | null = null;
    // Between our "it's stale" verdict and our rename, another breaker removes the
    // stale lock and creates its own.
    const isPidAlive = (pid: number) => {
      if (pid === OTHER_PID && !winner) {
        fs.rmSync(vaultLockPath(dir));
        winner = plant(dir, { pid: WINNER_PID, createdAt: clock.now() });
        return false;
      }
      return pid === WINNER_PID;
    };
    const err = await acquireVaultLock({ dir, timeoutMs: 300, isPidAlive, ...clock }).catch((e) => e);
    expect(err).toBeInstanceOf(VaultLockTimeoutError);
    expect(err.holder.pid).toBe(WINNER_PID);
    expect(readVaultLock(dir)?.token).toBe(winner!.token);
    expect(readVaultLock(dir)?.token).not.toBe(stale.token);
    expect(fs.readdirSync(dir)).toEqual(["vault.lock"]);
  });

  it("many in-process waiters racing a stale lock: exactly one holder at a time, all finish", async () => {
    const dir = tempDir();
    plant(dir, { pid: OTHER_PID });
    let inside = 0;
    let maxInside = 0;
    const order: number[] = [];
    await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        withVaultLock(
          async () => {
            inside += 1;
            maxInside = Math.max(maxInside, inside);
            await new Promise((r) => setTimeout(r, 2));
            order.push(i);
            inside -= 1;
          },
          { dir, isPidAlive: (pid) => pid !== OTHER_PID },
        ),
      ),
    );
    expect(maxInside).toBe(1);
    expect(order.sort()).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
  });
});

describe("nesting / re-entrancy", () => {
  it("is re-entrant within one async call chain (same token, no deadlock)", async () => {
    const dir = tempDir();
    const tokens = await withVaultLock(async () => {
      const outer = currentVaultLockToken(dir);
      const inner = await withVaultLock(async () => {
        await new Promise((r) => setTimeout(r, 1));
        return withVaultLock(() => currentVaultLockToken(dir), { dir, timeoutMs: 50 });
      }, { dir, timeoutMs: 50 });
      expect(fs.existsSync(vaultLockPath(dir))).toBe(true); // inner exit did not release
      return { outer, inner };
    }, { dir });
    expect(tokens.outer).toBeDefined();
    expect(tokens.inner).toBe(tokens.outer);
    expect(fs.existsSync(vaultLockPath(dir))).toBe(false);
  });

  it("locks for different vault dirs are independent", async () => {
    const a = tempDir();
    const b = tempDir();
    await withVaultLock(async () => {
      expect(isVaultLockHeld(a)).toBe(true);
      expect(isVaultLockHeld(b)).toBe(false);
      await withVaultLock(() => expect(isVaultLockHeld(b)).toBe(true), { dir: b });
    }, { dir: a });
  });

  it("independent async flows in one process do not share the lock", async () => {
    const dir = tempDir();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const first = withVaultLock(() => gate, { dir });
    await new Promise((r) => setTimeout(r, 5));
    await expect(withVaultLock(() => 1, { dir, timeoutMs: 50 })).rejects.toBeInstanceOf(VaultLockTimeoutError);
    release();
    await first;
    expect(await withVaultLock(() => 2, { dir })).toBe(2);
  });
});

describe("assertVaultLockHeld", () => {
  it("throws outside the lock, passes inside, and throws once the lock was broken by someone else", async () => {
    const dir = tempDir();
    expect(() => assertVaultLockHeld(dir)).toThrow(VaultLockNotHeldError);
    await withVaultLock(() => {
      assertVaultLockHeld(dir);
      plant(dir, { pid: OTHER_PID });
      expect(() => assertVaultLockHeld(dir)).toThrow(/lost the vault lock/);
    }, { dir });
  });

  it("verifies an explicit token (agent side) against the lockfile", async () => {
    const dir = tempDir();
    const info = await acquireVaultLock({ dir });
    expect(() => assertVaultLockHeld(dir, info.token)).not.toThrow();
    expect(() => assertVaultLockHeld(dir, "forged")).toThrow(VaultLockNotHeldError);
    releaseVaultLock(info.token, dir);
    expect(() => assertVaultLockHeld(dir, info.token)).toThrow(VaultLockNotHeldError);
  });

  it("a holder whose lock was broken refuses to write (token no longer on disk)", async () => {
    const dir = tempDir();
    const holder = await acquireVaultLock({ dir });
    // Simulate maxHoldMs break: another process renamed ours away and took the slot.
    plant(dir, { pid: OTHER_PID });
    expect(() => assertVaultLockHeld(dir, holder.token)).toThrow(/lost the vault lock/);
    expect(releaseVaultLock(holder.token, dir)).toBe(false);
    expect(readVaultLock(dir)?.pid).toBe(OTHER_PID);
  });
});
