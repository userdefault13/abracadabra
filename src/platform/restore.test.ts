import { describe, it, expect, beforeEach, afterEach } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sealBundle, openBundle } from "../core/backup.js";
import { encryptVault, loadVault, writeEncryptedFile } from "../core/vault.js";
import { restoreMasterKey, resetPlatformForTests, getMasterKey } from "./index.js";

describe("restoreMasterKey (G2)", () => {
  const envBackup = { ...process.env };
  let tmpHome = "";

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "abra-restore-"));
    process.env.HOME = tmpHome;
    process.env.ABRA_DIR = path.join(tmpHome, ".abracadabra");
    process.env.ABRA_KEYSTORE = "passphrase-file";
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    process.env.ABRA_AUTH = "none";
    process.env.ABRA_HEADLESS_PASSPHRASE = "restore-test-passphrase";
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    resetPlatformForTests();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("persists bundle master key on passphrase-file keystore after USB restore", async () => {
    const bundlePass = "bundle-passphrase-12chars";
    const originKey = crypto.randomBytes(32);
    const vault = {
      version: 1 as const,
      projects: {
        gotest: {
          vars: {
            TOKEN: { value: "secret-value", secret: true, updatedAt: Date.now() },
          },
        },
      },
      connections: {},
    };
    const bundle = sealBundle(encryptVault(vault, originKey), originKey, bundlePass);
    const payload = openBundle(bundle, bundlePass);

    const freshHome = fs.mkdtempSync(path.join(os.tmpdir(), "abra-restore-b-"));
    process.env.HOME = freshHome;
    process.env.ABRA_DIR = path.join(freshHome, ".abracadabra");
    resetPlatformForTests();

    await restoreMasterKey(Buffer.from(payload.masterKey, "base64"), bundlePass);
    writeEncryptedFile(payload.vaultEnc);

    const loaded = await loadVault();
    expect(loaded.projects.gotest.vars.TOKEN.value).toBe("secret-value");
    const localKey = await getMasterKey();
    expect(localKey.equals(originKey)).toBe(true);

    fs.rmSync(freshHome, { recursive: true, force: true });
  });

  it("requires bundle passphrase for passphrase-file restore", async () => {
    const key = crypto.randomBytes(32);
    await expect(restoreMasterKey(key)).rejects.toThrow(/bundle passphrase/i);
  });
});
