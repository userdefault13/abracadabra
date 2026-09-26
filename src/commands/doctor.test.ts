import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { cmdDoctor } from "./doctor.js";
import { resetPlatformForTests } from "../platform/index.js";

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
});
