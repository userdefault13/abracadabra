import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
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

  it("defaults linux/win to keytar + password when polkit unavailable", () => {
    if (process.platform !== "linux" && process.platform !== "win32") return;
    delete process.env.ABRA_KEYSTORE;
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    setProbePolkitForTests(() => ({ ok: false, detail: "test" }));
    resetPlatformForTests();
    setProbePolkitForTests(() => ({ ok: false, detail: "test" }));
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

  beforeEach(() => {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_KEYSTORE;
    resetPlatformForTests();
  });

  afterEach(() => {
    process.env = { ...envBackup };
    Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
    resetPlatformForTests();
    vi.restoreAllMocks();
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

  it("falls back to password + stderr warning when probe not ok", () => {
    setProbePolkitForTests(() => ({ ok: false, detail: "missing policy" }));
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    expect(resolveAuthBackend()).toBe("password");
    expect(createAuth().id).toBe("password");
    expect(stderrSpy.mock.calls.some((c) => String(c[0]).includes("install-polkit"))).toBe(true);
    // one-shot
    stderrSpy.mockClear();
    expect(resolveAuthBackend()).toBe("password");
    expect(stderrSpy).not.toHaveBeenCalled();
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
