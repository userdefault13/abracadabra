import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { assertCloudPassphrase, assertUsbPassphrase, CLOUD_PASSPHRASE_MIN } from "./passphrase.js";
import { saveSyncState, loadSyncState } from "./sync.js";
import type { Vault } from "./vault.js";
import { resetPlatformForTests, restoreMasterKey, getMasterKey } from "../platform/index.js";

describe("passphrase policy", () => {
  it("accepts USB min length 8", () => {
    expect(() => assertUsbPassphrase("12345678")).not.toThrow();
    expect(() => assertUsbPassphrase("short")).toThrow(/8/);
  });

  it("rejects weak cloud passphrases", () => {
    expect(() => assertCloudPassphrase("short")).toThrow(/16/);
    expect(() => assertCloudPassphrase("aaaaaaaaaaaaaaaa")).toThrow();
    expect(() => assertCloudPassphrase("password12345678")).toThrow();
    expect(() => assertCloudPassphrase("alllowercasewordss")).toThrow(/3 of/);
  });

  it("accepts strong cloud passphrases", () => {
    expect(() => assertCloudPassphrase("Tr0ub4dor&3xtra!!")).not.toThrow();
    expect(CLOUD_PASSPHRASE_MIN).toBe(16);
  });
});

describe("encrypted sync-state", () => {
  const envBackup = { ...process.env };
  let tmpHome = "";
  const master = crypto.randomBytes(32);

  beforeEach(async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "abra-sync-"));
    process.env.HOME = tmpHome;
    process.env.ABRA_DIR = path.join(tmpHome, ".abracadabra");
    process.env.ABRA_KEYSTORE = "passphrase-file";
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_HEADLESS_PASSPHRASE = "sync-state-test-passphrase";
    resetPlatformForTests();
    await restoreMasterKey(master, "sync-state-test-passphrase");
    await getMasterKey();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    resetPlatformForTests();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("round-trips vault base without plaintext on disk", async () => {
    const vault: Vault = {
      version: 1,
      projects: {
        p: { createdAt: 1, vars: { SECRET: { value: "s3cret", secret: true, updatedAt: 1 } } },
      },
    };
    await saveSyncState(vault);
    const raw = fs.readFileSync(path.join(tmpHome, ".abracadabra", "sync-state.json"), "utf8");
    expect(raw).not.toContain("s3cret");
    expect(JSON.parse(raw).format).toBe("abracadabra-sync-state");
    const loaded = await loadSyncState();
    expect(loaded?.base.projects.p.vars.SECRET.value).toBe("s3cret");
  });

  it("migrates legacy plaintext sync-state", async () => {
    const vault: Vault = {
      version: 1,
      projects: { a: { createdAt: 1, vars: { K: { value: "v", secret: true, updatedAt: 1 } } } },
    };
    fs.mkdirSync(path.join(tmpHome, ".abracadabra"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(tmpHome, ".abracadabra", "sync-state.json"),
      JSON.stringify({ lastSyncAt: 1, base: vault }),
      { mode: 0o600 },
    );
    const loaded = await loadSyncState();
    expect(loaded?.base.projects.a.vars.K.value).toBe("v");
    const raw = fs.readFileSync(path.join(tmpHome, ".abracadabra", "sync-state.json"), "utf8");
    expect(raw).not.toContain('"value":"v"');
    expect(JSON.parse(raw).format).toBe("abracadabra-sync-state");
  });
});
