import fs from "node:fs";
import path from "node:path";
import { abraDir, ensureDir } from "../core/paths.js";

const ATTEMPTS_FILE = "unlock-attempts.json";
const MAX_BACKOFF_SEC = 15 * 60; // 15 minutes
const FAILURES_BEFORE_BACKOFF = 5;

export type UnlockAttemptsState = {
  failures: number;
  lastFailureAt: number;
};

let nowFn: () => number = () => Date.now();

/** Test hook — inject a fake clock (or null to restore). */
export function setUnlockClockForTests(fn: (() => number) | null): void {
  nowFn = fn ?? (() => Date.now());
}

function attemptsPath(): string {
  return path.join(abraDir(), ATTEMPTS_FILE);
}

/**
 * Persistent failed-unlock counter. Speed bump against casual guessing; the real
 * cost is scrypt. Same-user can delete this file (or corrupt it) — we treat
 * missing/corrupt as zero rather than hard-failing, since FS access already
 * bypasses this counter.
 */
export function loadUnlockAttempts(): UnlockAttemptsState {
  try {
    const raw = JSON.parse(fs.readFileSync(attemptsPath(), "utf8")) as Partial<UnlockAttemptsState>;
    const failures = Number(raw.failures);
    const lastFailureAt = Number(raw.lastFailureAt);
    if (!Number.isFinite(failures) || failures < 0 || !Number.isFinite(lastFailureAt)) {
      return { failures: 0, lastFailureAt: 0 };
    }
    return { failures: Math.floor(failures), lastFailureAt };
  } catch {
    return { failures: 0, lastFailureAt: 0 };
  }
}

function saveUnlockAttempts(state: UnlockAttemptsState): void {
  ensureDir();
  const file = attemptsPath();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** Seconds of backoff required before the next attempt, given current failure count. */
export function backoffSecondsForFailures(failures: number): number {
  if (failures < FAILURES_BEFORE_BACKOFF) return 0;
  const sec = 2 ** (failures - FAILURES_BEFORE_BACKOFF);
  return Math.min(MAX_BACKOFF_SEC, sec);
}

/**
 * If currently in backoff, throw with remaining wait. Does not run scrypt.
 * Call before attempting passphrase unwrap.
 */
export function assertUnlockAllowed(): void {
  const state = loadUnlockAttempts();
  const waitSec = backoffSecondsForFailures(state.failures);
  if (waitSec <= 0) return;
  const elapsedSec = (nowFn() - state.lastFailureAt) / 1000;
  const remaining = Math.ceil(waitSec - elapsedSec);
  if (remaining > 0) {
    throw new Error(
      `Too many failed unlock attempts — wait ${remaining}s before trying again`,
    );
  }
}

/** Record a wrong-passphrase failure (not I/O errors). */
export function recordUnlockFailure(): void {
  const state = loadUnlockAttempts();
  saveUnlockAttempts({
    failures: state.failures + 1,
    lastFailureAt: nowFn(),
  });
}

/** Reset counter after a successful unlock. */
export function resetUnlockAttempts(): void {
  saveUnlockAttempts({ failures: 0, lastFailureAt: 0 });
}
