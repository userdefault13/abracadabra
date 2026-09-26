import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { cmdDoctor } from "./doctor.js";
import { resetPlatformForTests, platformInfo } from "../platform/index.js";

type PlatformInfo = ReturnType<typeof platformInfo>;

function baseInfo(overrides: Partial<PlatformInfo> = {}): PlatformInfo {
  return {
    platform: "linux",
    keystore: "passphrase-file",
    auth: "passphrase",
    authSelectionReason: "platform default",
    keystoreSelectionReason: "auto-detected master.key.enc (linux)",
    biometricsSkipped: false,
    vaultLocked: true,
    headless: { headless: true, reasons: ["SSH_CONNECTION set"] },
    ...overrides,
  };
}

describe("cmdDoctor headless / passphrase", () => {
  const envBackup = { ...process.env };
  const realPlatform = process.platform;
  let lines: string[] = [];
  let tmpDir = "";

  beforeEach(() => {
    lines = [];
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-doctor-"));
    process.env.ABRA_DIR = tmpDir;
    vi.spyOn(console, "log").mockImplementation((msg: string) => {
      lines.push(String(msg));
    });
    // Avoid process.exit(1) ending the suite.
    vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.ABRA_AUTH;
    delete process.env.ABRA_KEYSTORE;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    delete process.env.XDG_SESSION_TYPE;
    process.env.SSH_CONNECTION = "10.0.0.1 22 10.0.0.2 22";
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

  it("headless + keytar warns and counts as fail", async () => {
    // default keystore on linux = keytar
    await cmdDoctor();
    expect(lines.some((l) => l.startsWith("warn") && l.includes("passphrase-file"))).toBe(true);
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it("passphrase auth prints ok line about terminal prompts", async () => {
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_KEYSTORE = "passphrase-file";
    await cmdDoctor();
    expect(
      lines.some(
        (l) =>
          l.startsWith("ok") &&
          l.includes("reveals prompt for the vault passphrase on the terminal"),
      ),
    ).toBe(true);
    expect(lines.some((l) => l.includes("auth backend passphrase"))).toBe(true);
    expect(lines.some((l) => l.includes("polkit not required"))).toBe(true);
  });

  it("reports abra-agent disabled when ABRA_AGENT=0", async () => {
    process.env.ABRA_AGENT = "0";
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_KEYSTORE = "passphrase-file";
    await cmdDoctor();
    expect(
      lines.some(
        (l) => l.startsWith("ok") && l.includes("abra-agent disabled (ABRA_AGENT=0)"),
      ),
    ).toBe(true);
  });

  it("reports agent socket path + source + reason", async () => {
    delete process.env.ABRA_AGENT;
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_KEYSTORE = "passphrase-file";
    await cmdDoctor({
      agentEnabled: () => true,
      resolveRuntimeBase: () => ({
        dir: "/run/user/1000",
        source: "run-user-fallback",
        reason: "XDG_RUNTIME_DIR unset",
      }),
      resolveSocketPath: () => "/run/user/1000/abra/agent.sock",
      // Avoid real socket probe in this test.
      probeAgentStatus: async () => "unlocked",
    });
    expect(
      lines.some(
        (l) =>
          l.startsWith("ok") &&
          l.includes("abra-agent socket /run/user/1000/abra/agent.sock") &&
          l.includes("via /run/user/<uid> fallback: XDG_RUNTIME_DIR unset"),
      ),
    ).toBe(true);
  });
});

describe("cmdDoctor auto-detect keystore + agent risk", () => {
  const envBackup = { ...process.env };
  const realPlatform = process.platform;
  let lines: string[] = [];
  let tmpDir = "";

  beforeEach(() => {
    lines = [];
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "abra-doctor-ad-"));
    process.env.ABRA_DIR = tmpDir;
    vi.spyOn(console, "log").mockImplementation((msg: string) => {
      lines.push(String(msg));
    });
    vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    process.env.ABRA_AUTH = "passphrase";
    delete process.env.ABRA_KEYSTORE;
    delete process.env.ABRA_SKIP_BIOMETRICS;
    delete process.env.SSH_CONNECTION;
    process.env.DISPLAY = ":0";
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

  function hasAutoDetectWarning(): boolean {
    return lines.some(
      (l) =>
        l.startsWith("warn") &&
        l.includes("keystore auto-detected as passphrase-file") &&
        l.includes("upgrading-existing-units"),
    );
  }

  it("auto-detected + locked → warning", async () => {
    await cmdDoctor({
      platformInfo: () => baseInfo({ vaultLocked: true }),
      probeAgentStatus: async () => "locked",
      agentEnabled: () => true,
      resolveRuntimeBase: () => ({
        dir: "/run/user/1000",
        source: "run-user-fallback",
        reason: "XDG_RUNTIME_DIR unset",
      }),
      resolveSocketPath: () => "/run/user/1000/abra/agent.sock",
    });
    expect(hasAutoDetectWarning()).toBe(true);
    expect(lines.some((l) => l.includes("abra-agent is locked"))).toBe(true);
  });

  it("auto-detected + not running → warning", async () => {
    await cmdDoctor({
      platformInfo: () => baseInfo(),
      probeAgentStatus: async () => "not_running",
      agentEnabled: () => true,
      resolveRuntimeBase: () => ({
        dir: "/run/user/1000",
        source: "run-user-fallback",
        reason: "XDG_RUNTIME_DIR unset",
      }),
      resolveSocketPath: () => "/run/user/1000/abra/agent.sock",
    });
    expect(hasAutoDetectWarning()).toBe(true);
    expect(lines.some((l) => l.includes("abra-agent is not running"))).toBe(true);
  });

  it("auto-detected + unlocked → no warning", async () => {
    await cmdDoctor({
      platformInfo: () => baseInfo({ vaultLocked: false }),
      probeAgentStatus: async () => "unlocked",
      agentEnabled: () => true,
      resolveRuntimeBase: () => ({
        dir: "/run/user/1000",
        source: "run-user-fallback",
        reason: "XDG_RUNTIME_DIR unset",
      }),
      resolveSocketPath: () => "/run/user/1000/abra/agent.sock",
    });
    expect(hasAutoDetectWarning()).toBe(false);
  });

  it("explicit ABRA_KEYSTORE=passphrase-file + locked → no auto-detect warning", async () => {
    await cmdDoctor({
      platformInfo: () =>
        baseInfo({
          keystoreSelectionReason: "explicit ABRA_KEYSTORE",
          vaultLocked: true,
        }),
      probeAgentStatus: async () => "locked",
      agentEnabled: () => true,
      resolveRuntimeBase: () => ({
        dir: "/run/user/1000",
        source: "XDG_RUNTIME_DIR",
        reason: "XDG_RUNTIME_DIR set",
      }),
      resolveSocketPath: () => "/run/user/1000/abra/agent.sock",
    });
    expect(hasAutoDetectWarning()).toBe(false);
  });

  it("non-linux → no auto-detect warning", async () => {
    await cmdDoctor({
      platformInfo: () =>
        baseInfo({
          platform: "darwin",
          keystore: "macos-keychain",
          auth: "macos-touchid",
          keystoreSelectionReason: "platform default",
          vaultLocked: false,
          headless: { headless: false, reasons: ["not linux (darwin)"] },
        }),
      probeAgentStatus: async () => "not_running",
      pathDeps: { platform: "darwin", env: {} },
    });
    expect(hasAutoDetectWarning()).toBe(false);
  });
});
