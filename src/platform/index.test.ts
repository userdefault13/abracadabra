import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createAuth,
  createKeystore,
  platformInfo,
  resetPlatformForTests,
  biometricsSkipped,
  setProbePolkitForTests,
  resolveAuthBackend,
} from "./index.js";

describe("platform", () => {
  const envBackup = { ...process.env };
  const realPlatform = process.platform;

  beforeEach(() => {
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
    resetPlatformForTests();
    vi.restoreAllMocks();
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

  it("defaults win32 to keytar + password", () => {
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
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

describe("linux auth selection", () => {
  const envBackup = { ...process.env };
  const realPlatform = process.platform;
  let tmpDir = "";

  beforeEach(() => {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_KEYSTORE;
    // Hermetic: do not auto-detect a real ~/.abracadabra/master.key.enc on the host.
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-plat-"));
    process.env.ABRA_DIR = tmpDir;
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
    resetPlatformForTests();
    vi.restoreAllMocks();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it("selects polkit when probe ok", () => {
    setProbePolkitForTests(() => ({
      ok: true,
      pkcheck: "/usr/bin/pkcheck",
      policy: "/usr/share/polkit-1/actions/dev.abracadabra.policy",
    }));
    expect(resolveAuthBackend()).toBe("polkit");
    expect(createAuth().id).toBe("polkit");
  });

  it("still selects polkit (no password fallback, no stderr warning) when probe not ok", () => {
    setProbePolkitForTests(() => ({ ok: false, detail: "missing policy" }));
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    expect(resolveAuthBackend()).toBe("polkit");
    expect(createAuth().id).toBe("polkit");
    expect(platformInfo().auth).toBe("polkit");
    expect(stderrSpy).not.toHaveBeenCalled();
  });

  it("ABRA_AUTH=password is honored as explicit opt-in even when probe not ok", () => {
    setProbePolkitForTests(() => ({ ok: false, detail: "missing policy" }));
    process.env.ABRA_AUTH = "password";
    expect(resolveAuthBackend()).toBe("password");
    expect(createAuth().id).toBe("password");
  });

  it("ABRA_AUTH overrides still win", () => {
    setProbePolkitForTests(() => ({ ok: true, pkcheck: "/x", policy: "/y" }));
    process.env.ABRA_AUTH = "password";
    expect(resolveAuthBackend()).toBe("password");
    expect(createAuth().id).toBe("password");
  });

  it("ABRA_SKIP_BIOMETRICS -> none", () => {
    setProbePolkitForTests(() => ({ ok: true, pkcheck: "/x", policy: "/y" }));
    process.env.ABRA_SKIP_BIOMETRICS = "1";
    expect(resolveAuthBackend()).toBe("none");
    expect(createAuth().id).toBe("none");
  });

  it("headless + passphrase-file selects passphrase", () => {
    process.env.ABRA_KEYSTORE = "passphrase-file";
    process.env.SSH_CONNECTION = "10.0.0.1 22 10.0.0.2 22";
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    expect(resolveAuthBackend()).toBe("passphrase");
    expect(createAuth().id).toBe("passphrase");
  });

  it("createAuth returns PassphraseAuth for ABRA_AUTH=passphrase", () => {
    process.env.ABRA_AUTH = "passphrase";
    expect(createAuth().id).toBe("passphrase");
  });

  it("unknown ABRA_AUTH lists valid values", () => {
    process.env.ABRA_AUTH = "nope-backend";
    expect(() => createAuth()).toThrow(/Valid values:.*passphrase/);
    expect(() => createAuth()).toThrow(/polkit/);
  });

  it("rejects ABRA_AUTH=polkit on non-linux", () => {
    Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
    process.env.ABRA_AUTH = "polkit";
    expect(() => createAuth()).toThrow(/requires Linux/);
  });
});

describe("darwin auth unchanged under linux mocks restored", () => {
  const envBackup = { ...process.env };
  const realPlatform = process.platform;

  afterEach(() => {
    process.env = { ...envBackup };
    Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
    resetPlatformForTests();
  });

  it("darwin still defaults to macos-touchid", () => {
    if (realPlatform !== "darwin") return;
    Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    resetPlatformForTests();
    expect(resolveAuthBackend()).toBe("macos-touchid");
    expect(createAuth().id).toBe("macos-touchid");
  });
});
