import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createAuth,
  createKeystore,
  platformInfo,
  resetPlatformForTests,
  biometricsSkipped,
} from "./index.js";

describe("platform", () => {
  const envBackup = { ...process.env };

  beforeEach(() => {
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    resetPlatformForTests();
  });

  it("reports darwin backends on macOS", () => {
    if (process.platform !== "darwin") return;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_KEYSTORE;
    resetPlatformForTests();
    const info = platformInfo();
    expect(info.keystore).toBe("macos-keychain");
    expect(info.auth).toBe("macos-touchid");
  });

  it("defaults linux/win to keytar + password", () => {
    if (process.platform !== "linux" && process.platform !== "win32") return;
    delete process.env.ABRA_KEYSTORE;
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    resetPlatformForTests();
    const info = platformInfo();
    expect(info.keystore).toBe("keytar");
    expect(info.auth).toBe("password");
    expect(createAuth().id).toBe("password");
  });

  it("uses none auth when ABRA_SKIP_BIOMETRICS=1", () => {
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    resetPlatformForTests();
    expect(biometricsSkipped()).toBe(true);
    expect(createAuth().id).toBe("none");
    return createAuth().authenticate({ reason: "test" });
  });

  it("honors ABRA_AUTH override", () => {
    process.env.ABRA_AUTH = "none";
    resetPlatformForTests();
    expect(createAuth().id).toBe("none");
  });

  it("creates passphrase-file keystore when requested", () => {
    process.env.ABRA_KEYSTORE = "passphrase-file";
    expect(createKeystore().id).toBe("passphrase-file");
  });

  it("throws on unknown ABRA_KEYSTORE", () => {
    process.env.ABRA_KEYSTORE = "nope";
    expect(() => createKeystore()).toThrow(/Unknown ABRA_KEYSTORE/);
  });
});
