import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { EventEmitter } from "node:events";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassphraseAuth, sanitizeAuthReason } from "./auth-passphrase.js";
import { writeMasterKeyFile, setDefaultKdfForTests } from "./master-key-file.js";
import {
  getSessionMasterKey,
  lockSession,
  unlockSession,
  resetSessionForTests,
  isSessionUnlocked,
} from "./session.js";
import {
  loadUnlockAttempts,
  recordUnlockFailure,
  resetUnlockAttempts,
  setUnlockClockForTests,
} from "./unlock-attempts.js";
import { NoTerminalError, setOpenTtyForTests, type TtyHandles } from "../core/prompt.js";
import { resetPlatformForTests } from "./index.js";

function makeFakeTty(answer: string): {
  openCount: () => number;
  writes: () => string[];
} {
  let openCount = 0;
  const writes: string[] = [];
  setOpenTtyForTests(() => {
    openCount++;
    const input = new EventEmitter() as TtyHandles["input"];
    input.isTTY = true;
    input.setRawMode = () => {};
    input.resume = () => {};
    input.pause = () => {};
    const output = {
      write(chunk: string | Uint8Array) {
        writes.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
        return true;
      },
    } as TtyHandles["output"];
    queueMicrotask(() => {
      for (const ch of answer) {
        input.emit("keypress", ch, {});
      }
      input.emit("keypress", "", { name: "return" });
    });
    return {
      input,
      output,
      close: () => {},
    };
  });
  return {
    openCount: () => openCount,
    writes: () => writes,
  };
}

describe("sanitizeAuthReason", () => {
  it("strips ANSI and control chars; newlines become spaces; truncates to 200", () => {
    expect(sanitizeAuthReason("hello\x1b[31mRED\x1b[0m")).toBe("helloRED");
    expect(sanitizeAuthReason("a\nb\rc")).toBe("a b c");
    expect(sanitizeAuthReason("x\u0001y\u009fz")).toBe("xyz");
    const long = "p".repeat(250);
    const out = sanitizeAuthReason(long);
    expect(out.length).toBe(201); // 200 + ellipsis
    expect(out.endsWith("…")).toBe(true);
  });
});

describe("PassphraseAuth", () => {
  const envBackup = { ...process.env };
  const argvBackup = [...process.argv];
  let tmpDir = "";
  let clock = 1_000_000;
  const pass = "correct-vault-passphrase";
  let masterKey: Buffer;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-auth-pp-"));
    process.env.ABRA_DIR = tmpDir;
    process.env.ABRA_KEYSTORE = "passphrase-file";
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_HEADLESS_PASSPHRASE;
    setDefaultKdfForTests({ N: 16384 });
    clock = 1_000_000;
    setUnlockClockForTests(() => clock);
    resetUnlockAttempts();
    resetSessionForTests();
    resetPlatformForTests();
    masterKey = crypto.randomBytes(32);
    writeMasterKeyFile(masterKey, pass, { kdf: { N: 16384 } });
  });

  afterEach(() => {
    process.env = { ...envBackup };
    process.argv = [...argvBackup];
    setOpenTtyForTests(null);
    setUnlockClockForTests(null);
    setDefaultKdfForTests(null);
    resetSessionForTests();
    resetPlatformForTests();
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("correct passphrase allows and resets unlock counter", async () => {
    for (let i = 0; i < 3; i++) recordUnlockFailure();
    expect(loadUnlockAttempts().failures).toBe(3);
    makeFakeTty(pass);
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal FOO" })).resolves.toBeUndefined();
    expect(loadUnlockAttempts().failures).toBe(0);
  });

  it("wrong passphrase denies, increments persisted counter", async () => {
    makeFakeTty("wrong-passphrase!!");
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(
      "abracadabra: approval denied — wrong passphrase",
    );
    expect(loadUnlockAttempts().failures).toBe(1);
    const onDisk = JSON.parse(
      fs.readFileSync(path.join(tmpDir, "unlock-attempts.json"), "utf8"),
    ) as { failures: number };
    expect(onDisk.failures).toBe(1);
  });

  it("two authenticate() calls → two prompts", async () => {
    const fake = makeFakeTty(pass);
    const auth = new PassphraseAuth();
    await auth.authenticate({ reason: "a" });
    await auth.authenticate({ reason: "b" });
    expect(fake.openCount()).toBe(2);
    expect(fake.writes().filter((w) => w.includes("Vault passphrase")).length).toBe(2);
  });

  it("no TTY → exact denial, zero prompts, counter unchanged", async () => {
    let opens = 0;
    setOpenTtyForTests(() => {
      opens++;
      throw new NoTerminalError();
    });
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(
      "abracadabra: approval denied — passphrase approval needs a terminal: use ssh -t (MCP/API access while headless comes with `abra grant`)",
    );
    expect(opens).toBe(1);
    expect(loadUnlockAttempts().failures).toBe(0);
  });

  it("writes nothing when tty open fails", async () => {
    const writes: string[] = [];
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation((c) => {
      writes.push(String(c));
      return true;
    });
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation((c) => {
      writes.push(String(c));
      return true;
    });
    setOpenTtyForTests(() => {
      throw new NoTerminalError();
    });
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "x" })).rejects.toThrow(/approval denied/);
    expect(writes).toEqual([]);
    stderrSpy.mockRestore();
    stdoutSpy.mockRestore();
  });

  it("ABRA_HEADLESS_PASSPHRASE without skip flags is ignored (still uses tty)", async () => {
    process.env.ABRA_HEADLESS_PASSPHRASE = pass;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_AUTH;
    const fake = makeFakeTty(pass);
    const auth = new PassphraseAuth();
    await auth.authenticate({ reason: "reveal" });
    expect(fake.openCount()).toBe(1);
  });

  it("ABRA_HEADLESS_PASSPHRASE with ABRA_SKIP_BIOMETRICS=1 + ABRA_AUTH=passphrase is honored", async () => {
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_HEADLESS_PASSPHRASE = pass;
    let opens = 0;
    setOpenTtyForTests(() => {
      opens++;
      throw new NoTerminalError();
    });
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal" })).resolves.toBeUndefined();
    expect(opens).toBe(0);
  });

  it("argv --passphrase=… is never used", async () => {
    process.argv = ["node", "abra", `--passphrase=${pass}`];
    makeFakeTty("wrong-from-tty!!!!");
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(/wrong passphrase/);
  });

  it("non-passphrase-file keystore denies with keystore message and zero prompts", async () => {
    process.env.ABRA_KEYSTORE = "keytar";
    let opens = 0;
    setOpenTtyForTests(() => {
      opens++;
      return {
        input: new EventEmitter() as TtyHandles["input"],
        output: { write: () => true } as TtyHandles["output"],
        close: () => {},
      };
    });
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(
      /ABRA_AUTH=passphrase requires ABRA_KEYSTORE=passphrase-file \(current keystore: keytar\)/,
    );
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(
      /abra keystore migrate/,
    );
    expect(opens).toBe(0);
  });

  it("backoff active → refused without prompting", async () => {
    for (let i = 0; i < 5; i++) recordUnlockFailure();
    clock = 1_000_000;
    let opens = 0;
    setOpenTtyForTests(() => {
      opens++;
      throw new Error("should not open");
    });
    const auth = new PassphraseAuth();
    await expect(auth.authenticate({ reason: "reveal" })).rejects.toThrow(/wait \d+s/);
    expect(opens).toBe(0);
  });

  it("reason is sanitized in the prompt", async () => {
    const fake = makeFakeTty(pass);
    const auth = new PassphraseAuth();
    const dirty = `proj\x1b[31m\n${"x".repeat(250)}`;
    await auth.authenticate({ reason: dirty });
    const promptText = fake.writes().join("");
    expect(promptText).not.toContain("\x1b");
    expect(promptText).not.toContain("\x1b[31m");
    // Newlines in reason become spaces; ellipsis from truncation.
    expect(promptText).toMatch(/abracadabra: proj /);
    expect(promptText).toContain("…");
    expect(promptText).toContain("Vault passphrase to approve:");
  });

  it("success when session locked unlocks the session", async () => {
    lockSession();
    expect(isSessionUnlocked()).toBe(false);
    makeFakeTty(pass);
    await new PassphraseAuth().authenticate({ reason: "reveal" });
    expect(isSessionUnlocked()).toBe(true);
    expect(getSessionMasterKey()!.equals(masterKey)).toBe(true);
  });

  it("success when session already unlocked does not fail", async () => {
    unlockSession(masterKey);
    makeFakeTty(pass);
    await expect(new PassphraseAuth().authenticate({ reason: "reveal" })).resolves.toBeUndefined();
    expect(isSessionUnlocked()).toBe(true);
  });

  it("no master key file → deny without prompt", async () => {
    fs.rmSync(path.join(tmpDir, "master.key.enc"), { force: true });
    let opens = 0;
    setOpenTtyForTests(() => {
      opens++;
      throw new Error("no");
    });
    await expect(new PassphraseAuth().authenticate({ reason: "reveal" })).rejects.toThrow(
      /no vault master key file/,
    );
    expect(opens).toBe(0);
  });

  it("empty passphrase denies without counting", async () => {
    makeFakeTty("");
    await expect(new PassphraseAuth().authenticate({ reason: "reveal" })).rejects.toThrow(
      /empty passphrase/,
    );
    expect(loadUnlockAttempts().failures).toBe(0);
  });

  it("id and supportsBiometrics", () => {
    const auth = new PassphraseAuth();
    expect(auth.id).toBe("passphrase");
    expect(auth.supportsBiometrics()).toBe(false);
  });
});
