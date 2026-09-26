import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassphraseFileKeystore } from "./keystore-passphrase.js";
import {
  writeMasterKeyFile,
  loadMasterKeyFileRaw,
  setDefaultKdfForTests,
} from "./master-key-file.js";
import {
  getSessionMasterKey,
  lockSession,
  unlockSession,
  resetSessionForTests,
  isSessionUnlocked,
} from "./session.js";
import {
  assertUnlockAllowed,
  backoffSecondsForFailures,
  loadUnlockAttempts,
  recordUnlockFailure,
  resetUnlockAttempts,
  setUnlockClockForTests,
} from "./unlock-attempts.js";
import { promptHidden, setOpenTtyForTests } from "../core/prompt.js";
import * as promptMod from "../core/prompt.js";
import { headlessPassphrase } from "./env.js";
import { resetPlatformForTests } from "./index.js";

describe("session (no cached passphrase)", () => {
  afterEach(() => {
    resetSessionForTests();
  });

  it("stores a copy of the master key and zeros it on lock", () => {
    const key = crypto.randomBytes(32);
    const original = Buffer.from(key);
    unlockSession(key);
    key.fill(0xff);
    const cached = getSessionMasterKey();
    expect(cached).not.toBeNull();
    expect(cached!.equals(original)).toBe(true);
    lockSession();
    expect(isSessionUnlocked()).toBe(false);
    expect(getSessionMasterKey()).toBeNull();
  });

  it("zeros key on TTL expiry", () => {
    const prev = process.env.ABRA_UNLOCK_TTL_SECONDS;
    process.env.ABRA_UNLOCK_TTL_SECONDS = "0.001";
    const key = crypto.randomBytes(32);
    unlockSession(key);
    const start = Date.now();
    while (Date.now() - start < 5) {
      /* spin until TTL elapses */
    }
    expect(isSessionUnlocked()).toBe(false);
    expect(getSessionMasterKey()).toBeNull();
    if (prev === undefined) delete process.env.ABRA_UNLOCK_TTL_SECONDS;
    else process.env.ABRA_UNLOCK_TTL_SECONDS = prev;
  });
});

describe("headlessPassphrase gate", () => {
  const envBackup = { ...process.env };

  afterEach(() => {
    process.env = { ...envBackup };
  });

  it("ignores ABRA_HEADLESS_PASSPHRASE without skip flags", () => {
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_AUTH;
    process.env.ABRA_HEADLESS_PASSPHRASE = "should-be-ignored";
    expect(headlessPassphrase()).toBeUndefined();
  });

  it("honors ABRA_HEADLESS_PASSPHRASE with ABRA_SKIP_BIOMETRICS=1", () => {
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_HEADLESS_PASSPHRASE = "ci-only-pass";
    expect(headlessPassphrase()).toBe("ci-only-pass");
  });

  it("honors ABRA_HEADLESS_PASSPHRASE with ABRA_AUTH=none", () => {
    delete process.env.ABRA_SKIP_BIOMETRICS;
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_HEADLESS_PASSPHRASE = "ci-auth-none";
    expect(headlessPassphrase()).toBe("ci-auth-none");
  });
});

describe("promptHidden tty", () => {
  const envBackup = { ...process.env };

  beforeEach(() => {
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_HEADLESS_PASSPHRASE;
  });

  afterEach(() => {
    process.env = { ...envBackup };
    setOpenTtyForTests(null);
    vi.restoreAllMocks();
  });

  it("refuses with message containing 'no terminal: use ssh -t'", async () => {
    setOpenTtyForTests(() => {
      throw new Error("abracadabra: no terminal: use ssh -t");
    });
    await expect(promptHidden("pass? ")).rejects.toThrow(/no terminal: use ssh -t/);
  });

  it("ignores ABRA_HEADLESS_PASSPHRASE in prompt when skip flags unset", async () => {
    process.env.ABRA_HEADLESS_PASSPHRASE = "env-pass-should-ignore";
    setOpenTtyForTests(() => {
      throw new Error("abracadabra: no terminal: use ssh -t");
    });
    await expect(promptHidden("pass? ")).rejects.toThrow(/no terminal/);
  });

  it("returns headless passphrase when skip flags set (no tty needed)", async () => {
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_HEADLESS_PASSPHRASE = "headless-ok";
    const v = await promptHidden("pass? ");
    expect(v).toBe("headless-ok");
  });
});

describe("unlock backoff", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";
  let clock = 1_000_000;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-backoff-"));
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_KEYSTORE = "passphrase-file";
    setDefaultKdfForTests({ N: 16384 });
    clock = 1_000_000;
    setUnlockClockForTests(() => clock);
    resetUnlockAttempts();
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    setUnlockClockForTests(null);
    setDefaultKdfForTests(null);
    resetSessionForTests();
    resetPlatformForTests();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("computes exponential backoff capped at 15 minutes", () => {
    expect(backoffSecondsForFailures(4)).toBe(0);
    expect(backoffSecondsForFailures(5)).toBe(1);
    expect(backoffSecondsForFailures(6)).toBe(2);
    expect(backoffSecondsForFailures(7)).toBe(4);
    expect(backoffSecondsForFailures(5 + 10)).toBe(15 * 60);
    expect(backoffSecondsForFailures(5 + 20)).toBe(15 * 60);
  });

  it("persists failures across a fresh keystore instance and blocks scrypt during backoff", async () => {
    const pass = "correct-passphrase";
    const key = crypto.randomBytes(32);
    writeMasterKeyFile(key, pass, { kdf: { N: 16384 } });

    const ks1 = new PassphraseFileKeystore();
    for (let i = 0; i < 5; i++) {
      await expect(ks1.unlockWithPassphrase("wrong-password!!")).rejects.toThrow(/Wrong passphrase/);
    }
    expect(loadUnlockAttempts().failures).toBe(5);

    const ks2 = new PassphraseFileKeystore();
    const scryptSpy = vi.spyOn(crypto, "scryptSync");
    clock = 1_000_000;
    await expect(ks2.unlockWithPassphrase("wrong-password!!")).rejects.toThrow(/wait \d+s/);
    expect(scryptSpy).not.toHaveBeenCalled();
    scryptSpy.mockRestore();

    clock += 2000;
    await ks2.unlockWithPassphrase(pass);
    expect(loadUnlockAttempts().failures).toBe(0);
    expect(getSessionMasterKey()!.equals(key)).toBe(true);
  });

  it("does not record I/O errors as unlock failures", async () => {
    const ks = new PassphraseFileKeystore();
    await expect(ks.unlockWithPassphrase("anything-here")).rejects.toThrow(/No master key/);
    expect(loadUnlockAttempts().failures).toBe(0);
  });

  it("assertUnlockAllowed throws with remaining wait", () => {
    for (let i = 0; i < 5; i++) recordUnlockFailure();
    clock = 1_000_000;
    expect(() => assertUnlockAllowed()).toThrow(/wait 1s/);
    clock += 1000;
    expect(() => assertUnlockAllowed()).not.toThrow();
  });
});

describe("PassphraseFileKeystore init min length", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-ks-"));
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_KEYSTORE = "passphrase-file";
    setDefaultKdfForTests({ N: 16384 });
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    setDefaultKdfForTests(null);
    vi.restoreAllMocks();
    resetPlatformForTests();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects 11-char passphrase at creation; accepts 12", async () => {
    const spy = vi
      .spyOn(promptMod, "promptHidden")
      .mockResolvedValueOnce("a".repeat(11))
      .mockResolvedValueOnce("a".repeat(11));

    const ks = new PassphraseFileKeystore();
    await expect(ks.initializeNewMasterKey()).rejects.toThrow(/at least 12/);

    spy.mockResolvedValueOnce("b".repeat(12)).mockResolvedValueOnce("b".repeat(12));
    const key = await ks.initializeNewMasterKey();
    expect(key.length).toBe(32);
    expect(loadMasterKeyFileRaw().version).toBe(2);
    expect(loadMasterKeyFileRaw().kdf.N).toBe(16384); // test default
  });
});

describe("getSessionPassphrase removed", () => {
  it("is not exported from session module", async () => {
    const mod = await import("./session.js");
    expect("getSessionPassphrase" in mod).toBe(false);
  });
});
