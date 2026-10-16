import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { cmdDoctor } from "./doctor.js";
import { resetPlatformForTests } from "../platform/index.js";

describe("cmdDoctor headless / passphrase", () => {
  const envBackup = { ...process.env };
  const realPlatform = process.platform;
  let lines: string[] = [];

  beforeEach(() => {
    lines = [];
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

  it("warns when the installed abra-agent unit lacks AF_NETLINK", async () => {
    const cfg = fs.mkdtempSync(path.join(os.tmpdir(), "abra-doctor-unit-"));
    try {
      const unitDir = path.join(cfg, "systemd", "user");
      fs.mkdirSync(unitDir, { recursive: true });
      fs.writeFileSync(
        path.join(unitDir, "abra-agent.service"),
        "[Service]\nExecStart=/usr/bin/node /x/dist/agent/server.js\nRestrictAddressFamilies=AF_UNIX\n",
      );
      process.env.XDG_CONFIG_HOME = cfg;
      await cmdDoctor();
      expect(
        lines.some((l) => l.startsWith("warn") && l.includes("abra-agent unit lacks AF_NETLINK")),
      ).toBe(true);
      expect(lines.some((l) => l.includes("systemctl --user daemon-reload"))).toBe(true);

      // A drop-in that adds AF_NETLINK fixes it.
      lines = [];
      fs.mkdirSync(path.join(unitDir, "abra-agent.service.d"));
      fs.writeFileSync(
        path.join(unitDir, "abra-agent.service.d", "netlink.conf"),
        "[Service]\nRestrictAddressFamilies=AF_NETLINK\n",
      );
      await cmdDoctor();
      expect(lines.some((l) => l.startsWith("ok") && l.includes("allows AF_NETLINK"))).toBe(true);
    } finally {
      fs.rmSync(cfg, { recursive: true, force: true });
    }
  });
});
