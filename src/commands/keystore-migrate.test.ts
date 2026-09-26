import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { cmdKeystoreMigrate, type MigrateSourceKeystore } from "./keystore-migrate.js";
import { KeystoreError } from "../platform/types.js";
import {
  loadMasterKeyFileRaw,
  masterKeyFileExists,
  readMasterKeyFile,
  setDefaultKdfForTests,
  writeMasterKeyFile,
} from "../platform/master-key-file.js";
import { masterKeyFile, vaultFile } from "../core/paths.js";
import { emptyVault, encryptVault, writeEncryptedVaultFile } from "../core/vault.js";
import { NoTerminalError } from "../core/prompt.js";

const PASS = "migrate-test-passphrase-ok";
const SHORT = "shortpass11"; // 11 chars

function makeSource(key: Buffer | null, opts?: { deleteFn?: () => Promise<void> }): MigrateSourceKeystore & {
  getCalls: number;
  deleteCalls: number;
  order: string[];
} {
  const order: string[] = [];
  let getCalls = 0;
  let deleteCalls = 0;
  const stored = key;
  return {
    order,
    get getCalls() {
      return getCalls;
    },
    get deleteCalls() {
      return deleteCalls;
    },
    async getMasterKey() {
      getCalls++;
      order.push("getMasterKey");
      if (stored == null) {
        throw new KeystoreError("not_found", "Master key not found in credential store");
      }
      return Buffer.from(stored);
    },
    async deleteMasterKey() {
      deleteCalls++;
      order.push("deleteMasterKey");
      if (opts?.deleteFn) await opts.deleteFn();
    },
  };
}

describe("cmdKeystoreMigrate", () => {
  const envBackup = { ...process.env };
  let tmpDir = "";
  let logs: string[] = [];
  let errs: string[] = [];

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-migrate-"));
    process.env.ABRA_DIR = tmpDir;
    setDefaultKdfForTests({ N: 16384 });
    logs = [];
    errs = [];
  });

  afterEach(() => {
    process.env = { ...envBackup };
    setDefaultKdfForTests(null);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function capture() {
    return {
      log: (m: string) => logs.push(m),
      error: (m: string) => errs.push(m),
    };
  }

  function allOutput(): string {
    return [...logs, ...errs].join("\n");
  }

  it("round trip: keytar → master.key.enc v2; vault decrypts; keytar untouched without --remove-old", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);
    writeEncryptedVaultFile(encryptVault(emptyVault(), key));

    const prompts: string[] = [];
    await cmdKeystoreMigrate(
      { to: "passphrase-file" },
      {
        platform: "linux",
        sourceKeystore: source,
        authenticate: async () => {},
        promptHidden: async (q) => {
          prompts.push(q);
          return PASS;
        },
        ...capture(),
      },
    );

    expect(masterKeyFileExists()).toBe(true);
    const raw = loadMasterKeyFileRaw();
    expect(raw.version).toBe(2);
    const opened = readMasterKeyFile(PASS);
    expect(crypto.timingSafeEqual(opened, key)).toBe(true);
    opened.fill(0);

    expect(source.deleteCalls).toBe(0);
    expect(allOutput()).toMatch(/Keytar copy kept/i);
    expect(allOutput()).toMatch(/ABRA_KEYSTORE=passphrase-file/);
    expect(allOutput()).not.toContain(key.toString("base64"));
    expect(allOutput()).not.toContain(key.toString("hex"));
    expect(allOutput()).not.toContain(PASS);
  });

  it("verify-before-delete: deleteMasterKey only after file verified", async () => {
    const key = crypto.randomBytes(32);
    const order: string[] = [];
    const source: MigrateSourceKeystore = {
      async getMasterKey() {
        order.push("getMasterKey");
        return Buffer.from(key);
      },
      async deleteMasterKey() {
        order.push("deleteMasterKey");
        // File must already exist and verify at this point
        expect(masterKeyFileExists()).toBe(true);
        const opened = readMasterKeyFile(PASS);
        expect(crypto.timingSafeEqual(opened, key)).toBe(true);
        opened.fill(0);
      },
    };
    writeEncryptedVaultFile(encryptVault(emptyVault(), key));

    let promptCount = 0;
    await cmdKeystoreMigrate(
      { to: "passphrase-file", removeOld: true },
      {
        platform: "linux",
        sourceKeystore: source,
        authenticate: async () => {},
        promptHidden: async () => {
          promptCount++;
          return PASS;
        },
        confirm: async () => {
          order.push("confirm-delete");
          expect(masterKeyFileExists()).toBe(true);
          return "delete";
        },
        ...capture(),
      },
    );

    expect(order).toEqual(["getMasterKey", "confirm-delete", "deleteMasterKey"]);
    expect(promptCount).toBe(2); // new + confirm passphrase
    expect(allOutput()).toMatch(/Removed master key from keytar/);
  });

  it("failed verify leaves keytar intact and renames master.key.enc to .failed-*", async () => {
    const keytarKey = crypto.randomBytes(32);
    const otherKey = crypto.randomBytes(32);
    const source = makeSource(keytarKey);
    // vault.enc encrypted with a DIFFERENT key → verify decrypt fails
    writeEncryptedVaultFile(encryptVault(emptyVault(), otherKey));

    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file", removeOld: true },
        {
          platform: "linux",
          sourceKeystore: source,
          authenticate: async () => {},
          promptHidden: async () => PASS,
          confirm: async () => "delete",
          now: () => 1234567890,
          ...capture(),
        },
      ),
    ).rejects.toThrow(/migration verify failed/);

    expect(source.deleteCalls).toBe(0);
    expect(fs.existsSync(masterKeyFile())).toBe(false);
    const failed = path.join(tmpDir, "master.key.enc.failed-1234567890");
    expect(fs.existsSync(failed)).toBe(true);
  });

  it("short passphrase (11 chars) rejected, nothing written, keytar intact", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);

    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          authenticate: async () => {},
          promptHidden: async () => SHORT,
          ...capture(),
        },
      ),
    ).rejects.toThrow(/at least 12/);

    expect(masterKeyFileExists()).toBe(false);
    expect(source.deleteCalls).toBe(0);
  });

  it("mismatched confirmation rejected", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);
    let n = 0;
    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          authenticate: async () => {},
          promptHidden: async () => {
            n++;
            return n === 1 ? PASS : PASS + "-other";
          },
          ...capture(),
        },
      ),
    ).rejects.toThrow(/do not match/i);

    expect(masterKeyFileExists()).toBe(false);
    expect(source.deleteCalls).toBe(0);
  });

  it("idempotent re-run: matching master.key.enc → already migrated, no rewrite", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);
    writeMasterKeyFile(key, PASS);
    writeEncryptedVaultFile(encryptVault(emptyVault(), key));
    const before = fs.readFileSync(masterKeyFile());
    const mtimeBefore = fs.statSync(masterKeyFile()).mtimeMs;

    // Ensure mtime can differ if rewritten
    await new Promise((r) => setTimeout(r, 20));

    await cmdKeystoreMigrate(
      { to: "passphrase-file" },
      {
        platform: "linux",
        sourceKeystore: source,
        authenticate: async () => {},
        promptHidden: async () => PASS,
        ...capture(),
      },
    );

    expect(allOutput()).toMatch(/already migrated/i);
    const after = fs.readFileSync(masterKeyFile());
    expect(Buffer.compare(before, after)).toBe(0);
    expect(fs.statSync(masterKeyFile()).mtimeMs).toBe(mtimeBefore);
    expect(source.deleteCalls).toBe(0);
  });

  it("existing master.key.enc with DIFFERENT key → refuses, nothing changed", async () => {
    const keytarKey = crypto.randomBytes(32);
    const otherKey = crypto.randomBytes(32);
    const source = makeSource(keytarKey);
    writeMasterKeyFile(otherKey, PASS);
    const before = fs.readFileSync(masterKeyFile());

    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          authenticate: async () => {},
          promptHidden: async () => PASS,
          ...capture(),
        },
      ),
    ).rejects.toThrow(/DIFFERENT key/);

    expect(Buffer.compare(before, fs.readFileSync(masterKeyFile()))).toBe(0);
    expect(source.deleteCalls).toBe(0);
  });

  it("keytar not_found + master.key.enc exists → exit 0 already on passphrase-file", async () => {
    const key = crypto.randomBytes(32);
    writeMasterKeyFile(key, PASS);
    const source = makeSource(null);

    await cmdKeystoreMigrate(
      { to: "passphrase-file" },
      {
        platform: "linux",
        sourceKeystore: source,
        authenticate: async () => {},
        promptHidden: async () => {
          throw new Error("should not prompt");
        },
        ...capture(),
      },
    );

    expect(allOutput()).toMatch(/already on passphrase-file/);
    expect(source.deleteCalls).toBe(0);
  });

  it("approval denied → nothing read/written", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);

    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          authenticate: async () => {
            throw new Error("approval denied");
          },
          promptHidden: async () => PASS,
          ...capture(),
        },
      ),
    ).rejects.toThrow(/approval denied/);

    expect(source.getCalls).toBe(0);
    expect(masterKeyFileExists()).toBe(false);
  });

  it("--remove-old but confirmation not delete → keytar kept", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);
    writeEncryptedVaultFile(encryptVault(emptyVault(), key));

    await cmdKeystoreMigrate(
      { to: "passphrase-file", removeOld: true },
      {
        platform: "linux",
        sourceKeystore: source,
        authenticate: async () => {},
        promptHidden: async () => PASS,
        confirm: async () => "nope",
        ...capture(),
      },
    );

    expect(masterKeyFileExists()).toBe(true);
    expect(source.deleteCalls).toBe(0);
    expect(allOutput()).toMatch(/keytar copy kept/i);
  });

  it("darwin → unsupported error", async () => {
    const source = makeSource(crypto.randomBytes(32));
    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "darwin",
          sourceKeystore: source,
          authenticate: async () => {},
          ...capture(),
        },
      ),
    ).rejects.toThrow(/macOS keychain is not supported yet/);
    expect(source.getCalls).toBe(0);
  });

  it("--to other → error", async () => {
    await expect(
      cmdKeystoreMigrate(
        { to: "keytar" },
        {
          platform: "linux",
          authenticate: async () => {},
          ...capture(),
        },
      ),
    ).rejects.toThrow(/Unsupported --to/);
  });

  it("--remove-old with no TTY refuses deletion", async () => {
    const key = crypto.randomBytes(32);
    const source = makeSource(key);
    writeEncryptedVaultFile(encryptVault(emptyVault(), key));

    await cmdKeystoreMigrate(
      { to: "passphrase-file", removeOld: true },
      {
        platform: "linux",
        sourceKeystore: source,
        authenticate: async () => {},
        promptHidden: async () => PASS,
        confirm: async () => {
          throw new NoTerminalError();
        },
        ...capture(),
      },
    );

    expect(masterKeyFileExists()).toBe(true);
    expect(source.deleteCalls).toBe(0);
    expect(allOutput()).toMatch(/refusing to delete|keytar copy kept/i);
  });

  it("keytar not_found without master.key.enc → error", async () => {
    const source = makeSource(null);
    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          authenticate: async () => {},
          ...capture(),
        },
      ),
    ).rejects.toThrow(/no master key in keytar/);
  });

  it("polkit denial on linux appends ABRA_AUTH=password SSH hint", async () => {
    const source = makeSource(crypto.randomBytes(32));
    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          resolveAuthBackend: () => "polkit",
          authenticate: async () => {
            throw new Error("polkit: Authentication failure");
          },
          ...capture(),
        },
      ),
    ).rejects.toThrow(/ABRA_AUTH=password abra keystore migrate/);
  });

  it("non-polkit auth errors are unchanged", async () => {
    const source = makeSource(crypto.randomBytes(32));
    await expect(
      cmdKeystoreMigrate(
        { to: "passphrase-file" },
        {
          platform: "linux",
          sourceKeystore: source,
          resolveAuthBackend: () => "passphrase",
          authenticate: async () => {
            throw new Error("wrong passphrase");
          },
          ...capture(),
        },
      ),
    ).rejects.toThrow(/^wrong passphrase$/);
  });
});
