import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { cmdDoctor } from "./doctor.js";
import {
  resetPlatformForTests,
  setMasterKeyFileProbeForTests,
} from "../platform/index.js";

/** Avoid flaky PATH / mise probes against the host machine. */
const quietPath = {
  whichOnPath: () => null as string | null,
};

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
    await cmdDoctor(quietPath);
    expect(lines.some((l) => l.startsWith("warn") && l.includes("passphrase-file"))).toBe(true);
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it("passphrase auth prints ok line about terminal prompts", async () => {
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_KEYSTORE = "passphrase-file";
    await cmdDoctor(quietPath);
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
      await cmdDoctor({
        whichOnPath: () => null,
        configHome: cfg,
      });
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
      await cmdDoctor({
        whichOnPath: () => null,
        configHome: cfg,
      });
      expect(lines.some((l) => l.startsWith("ok") && l.includes("allows AF_NETLINK"))).toBe(true);
    } finally {
      fs.rmSync(cfg, { recursive: true, force: true });
    }
  });

  it("ok when ABRA_KEYSTORE unset but unit sets Environment=ABRA_KEYSTORE", async () => {
    const cfg = fs.mkdtempSync(path.join(os.tmpdir(), "abra-doctor-ks-"));
    try {
      const unitDir = path.join(cfg, "systemd", "user");
      fs.mkdirSync(unitDir, { recursive: true });
      fs.writeFileSync(
        path.join(unitDir, "abra-agent.service"),
        "[Service]\nEnvironment=ABRA_KEYSTORE=passphrase-file\nExecStart=/usr/bin/node /x/dist/agent/server.js\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n",
      );
      delete process.env.ABRA_KEYSTORE;
      setMasterKeyFileProbeForTests(() => true);
      resetPlatformForTests();
      await cmdDoctor({
        ...quietPath,
        configHome: cfg,
        masterKeyExists: () => true,
      });
      expect(
        lines.some(
          (l) =>
            l.startsWith("ok") &&
            l.includes("ABRA_KEYSTORE unset") &&
            l.includes("Environment=ABRA_KEYSTORE=passphrase-file"),
        ),
      ).toBe(true);
    } finally {
      setMasterKeyFileProbeForTests(null);
      resetPlatformForTests();
      fs.rmSync(cfg, { recursive: true, force: true });
    }
  });

  it("ok when ABRA_KEYSTORE unset and master.key.enc auto-detects passphrase-file", async () => {
    delete process.env.ABRA_KEYSTORE;
    setMasterKeyFileProbeForTests(() => true);
    resetPlatformForTests();
    try {
      await cmdDoctor({
        ...quietPath,
        masterKeyExists: () => true,
        configHome: "/no/unit",
      });
      expect(
        lines.some(
          (l) =>
            l.startsWith("ok") &&
            l.includes("ABRA_KEYSTORE unset") &&
            l.includes("master.key.enc"),
        ),
      ).toBe(true);
    } finally {
      setMasterKeyFileProbeForTests(null);
      resetPlatformForTests();
    }
  });

  it("detects rejected mise shim and node PATH mismatch", async () => {
    process.env.ABRA_AUTH = "passphrase";
    process.env.ABRA_KEYSTORE = "passphrase-file";
    const { detectMiseAbraShim } = await import("./doctor.js");
    const mise = await detectMiseAbraShim("/home/u/.local/share/mise/shims/abra", {
      readlinkSync: () => "/home/u/.local/bin/mise",
      realpathSync: (p) => p,
      whichOnPath: (name) => (name === "mise" ? "/home/u/.local/bin/mise" : null),
      run: async () => ({
        stdout: "",
        stderr: "mise ERROR abra is not a valid shim",
        status: 1,
      }),
    });
    expect(mise.isMiseShim).toBe(true);
    expect(mise.miseRejects).toBe(true);

    await cmdDoctor({
      pathEnv: "/mise/shims:/usr/bin",
      whichOnPath: (name) => {
        if (name === "abra") return "/mise/shims/abra";
        if (name === "node") return "/usr/bin/node";
        if (name === "mise") return "/usr/bin/mise";
        return null;
      },
      readlinkSync: () => "/usr/bin/mise",
      realpathSync: (p) => p,
      readFileSync: () => "#!/bin/sh\nexec mise\n",
      run: async () => ({
        stdout: "",
        stderr: "mise ERROR abra is not a valid shim",
        status: 1,
      }),
      tryAgent: () => false,
      configHome: "/no/such/config",
      agentStatus: async () => ({
        locked: true,
        nodePath: "/mise/installs/node/26/bin/node",
      }),
    });
    expect(lines.some((l) => l.includes("mise shim") && l.includes("rejects"))).toBe(true);
  });
});
