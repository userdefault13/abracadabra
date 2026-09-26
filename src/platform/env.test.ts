import { describe, it, expect } from "vitest";
import {
  authSelectionReason,
  detectHeadlessSession,
  resolveAuthBackend,
  resolveKeystoreBackend,
  biometricsSkipped,
} from "./env.js";

type SshKind = "none" | "SSH_CONNECTION" | "SSH_TTY";
type DisplayKind = "none" | "DISPLAY" | "WAYLAND_DISPLAY";
type SessionKind = "unset" | "tty" | "wayland" | "x11";
type KeystoreKind = "unset" | "keytar" | "passphrase-file";
type AuthKind = "unset" | "polkit" | "passphrase" | "password" | "none";

function buildLinuxEnv(
  ssh: SshKind,
  display: DisplayKind,
  session: SessionKind,
  keystore: KeystoreKind,
  auth: AuthKind,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  // Explicitly clear headless / display signals.
  delete env.SSH_CONNECTION;
  delete env.SSH_TTY;
  delete env.DISPLAY;
  delete env.WAYLAND_DISPLAY;
  delete env.XDG_SESSION_TYPE;
  delete env.ABRA_KEYSTORE;
  delete env.ABRA_AUTH;
  delete env.ABRA_SKIP_BIOMETRICS;

  if (ssh === "SSH_CONNECTION") env.SSH_CONNECTION = "1.2.3.4 22 5.6.7.8 22";
  if (ssh === "SSH_TTY") env.SSH_TTY = "/dev/pts/0";
  if (display === "DISPLAY") env.DISPLAY = ":0";
  if (display === "WAYLAND_DISPLAY") env.WAYLAND_DISPLAY = "wayland-0";
  if (session !== "unset") env.XDG_SESSION_TYPE = session;
  if (keystore !== "unset") env.ABRA_KEYSTORE = keystore;
  if (auth !== "unset") env.ABRA_AUTH = auth;
  return env;
}

function expectedHeadless(ssh: SshKind, display: DisplayKind, session: SessionKind): boolean {
  if (ssh !== "none") return true;
  if (display !== "none") return false;
  if (session === "wayland" || session === "x11") return false;
  return true;
}

function expectedAuth(
  ssh: SshKind,
  display: DisplayKind,
  session: SessionKind,
  keystore: KeystoreKind,
  auth: AuthKind,
): string {
  if (auth !== "unset") return auth;
  const headless = expectedHeadless(ssh, display, session);
  const ks = keystore === "unset" ? "keytar" : keystore;
  if (headless && ks === "passphrase-file") return "passphrase";
  return "polkit";
}

describe("detectHeadlessSession", () => {
  it("non-linux is never headless", () => {
    expect(detectHeadlessSession({}, "darwin")).toEqual({
      headless: false,
      reasons: ["not linux (darwin)"],
    });
    expect(detectHeadlessSession({ SSH_CONNECTION: "x" }, "win32").headless).toBe(false);
  });

  it("SSH_CONNECTION marks headless", () => {
    const d = detectHeadlessSession(
      { SSH_CONNECTION: "10.0.0.1 22 10.0.0.2 22", DISPLAY: ":0" },
      "linux",
    );
    expect(d.headless).toBe(true);
    expect(d.reasons).toContain("SSH_CONNECTION set");
  });

  it("SSH_TTY marks headless", () => {
    const d = detectHeadlessSession({ SSH_TTY: "/dev/pts/1" }, "linux");
    expect(d.headless).toBe(true);
    expect(d.reasons).toContain("SSH_TTY set");
  });

  it("no display + XDG_SESSION_TYPE=tty is headless", () => {
    const d = detectHeadlessSession({ XDG_SESSION_TYPE: "tty" }, "linux");
    expect(d.headless).toBe(true);
    expect(d.reasons.some((r) => r.includes("XDG_SESSION_TYPE=tty"))).toBe(true);
  });

  it("no display + XDG unset is headless", () => {
    const d = detectHeadlessSession({}, "linux");
    expect(d.headless).toBe(true);
    expect(d.reasons.some((r) => r.includes("XDG_SESSION_TYPE=unset"))).toBe(true);
  });

  it("WAYLAND_DISPLAY is graphical", () => {
    const d = detectHeadlessSession(
      { WAYLAND_DISPLAY: "wayland-0", XDG_SESSION_TYPE: "wayland" },
      "linux",
    );
    expect(d.headless).toBe(false);
    expect(d.reasons).toContain("WAYLAND_DISPLAY set");
  });

  it("DISPLAY is graphical", () => {
    const d = detectHeadlessSession({ DISPLAY: ":0" }, "linux");
    expect(d.headless).toBe(false);
    expect(d.reasons).toContain("DISPLAY set");
  });

  it("XDG_SESSION_TYPE=x11 without DISPLAY is graphical", () => {
    const d = detectHeadlessSession({ XDG_SESSION_TYPE: "x11" }, "linux");
    expect(d.headless).toBe(false);
    expect(d.reasons).toContain("XDG_SESSION_TYPE=x11");
  });
});

describe("resolveAuthBackend linux selection matrix", () => {
  const sshKinds: SshKind[] = ["none", "SSH_CONNECTION", "SSH_TTY"];
  const displayKinds: DisplayKind[] = ["none", "DISPLAY", "WAYLAND_DISPLAY"];
  const sessionKinds: SessionKind[] = ["unset", "tty", "wayland", "x11"];
  const keystoreKinds: KeystoreKind[] = ["unset", "keytar", "passphrase-file"];
  const authKinds: AuthKind[] = ["unset", "polkit", "passphrase", "password", "none"];

  const cases: Array<{
    name: string;
    env: NodeJS.ProcessEnv;
    expected: string;
  }> = [];

  for (const ssh of sshKinds) {
    for (const display of displayKinds) {
      for (const session of sessionKinds) {
        for (const keystore of keystoreKinds) {
          for (const auth of authKinds) {
            const env = buildLinuxEnv(ssh, display, session, keystore, auth);
            cases.push({
              name: `ssh=${ssh} display=${display} xdg=${session} ks=${keystore} auth=${auth}`,
              env,
              expected: expectedAuth(ssh, display, session, keystore, auth),
            });
          }
        }
      }
    }
  }

  it(`covers ${cases.length} combinations`, () => {
    expect(cases.length).toBe(3 * 3 * 4 * 3 * 5);
  });

  it.each(cases)("$name → $expected", ({ env, expected }) => {
    expect(detectHeadlessSession(env, "linux").headless).toBe(
      expectedHeadless(
        (env.SSH_CONNECTION ? "SSH_CONNECTION" : env.SSH_TTY ? "SSH_TTY" : "none") as SshKind,
        env.WAYLAND_DISPLAY ? "WAYLAND_DISPLAY" : env.DISPLAY ? "DISPLAY" : "none",
        (env.XDG_SESSION_TYPE as SessionKind) || "unset",
      ),
    );
    expect(resolveAuthBackend(env, "linux")).toBe(expected);
  });

  it("never auto-resolves to password when ABRA_AUTH unset", () => {
    for (const c of cases) {
      if (c.env.ABRA_AUTH) continue;
      expect(resolveAuthBackend(c.env, "linux")).not.toBe("password");
    }
  });

  it("headless + passphrase-file auto-selects passphrase", () => {
    expect(
      resolveAuthBackend(
        { SSH_CONNECTION: "x", ABRA_KEYSTORE: "passphrase-file" },
        "linux",
      ),
    ).toBe("passphrase");
    expect(
      authSelectionReason(
        { SSH_CONNECTION: "x", ABRA_KEYSTORE: "passphrase-file" },
        "linux",
      ),
    ).toBe("headless + passphrase-file");
  });

  it("headless + keytar selects polkit (denies at auth time)", () => {
    expect(resolveAuthBackend({ SSH_TTY: "/dev/pts/0" }, "linux")).toBe("polkit");
    expect(authSelectionReason({ SSH_TTY: "/dev/pts/0" }, "linux")).toBe(
      "headless + keytar → polkit denies",
    );
  });

  it("graphical selects polkit", () => {
    expect(
      resolveAuthBackend({ DISPLAY: ":0", XDG_SESSION_TYPE: "x11" }, "linux"),
    ).toBe("polkit");
    expect(
      authSelectionReason({ DISPLAY: ":0", XDG_SESSION_TYPE: "x11" }, "linux"),
    ).toBe("graphical session");
  });
});

describe("resolveAuthBackend other platforms", () => {
  it("darwin → macos-touchid", () => {
    expect(resolveAuthBackend({}, "darwin")).toBe("macos-touchid");
  });

  it("win32 → password (unchanged)", () => {
    expect(resolveAuthBackend({}, "win32")).toBe("password");
  });

  it("skip flag → none", () => {
    expect(resolveAuthBackend({ ABRA_SKIP_BIOMETRICS: "1" }, "linux")).toBe("none");
    expect(resolveAuthBackend({ ABRA_SKIP_BIOMETRICS: "1" }, "darwin")).toBe("none");
    expect(biometricsSkipped({ ABRA_SKIP_BIOMETRICS: "1" })).toBe(true);
  });

  it("explicit ABRA_AUTH always wins", () => {
    expect(
      resolveAuthBackend(
        { ABRA_AUTH: "passphrase", ABRA_SKIP_BIOMETRICS: "1", DISPLAY: ":0" },
        "linux",
      ),
    ).toBe("passphrase");
    expect(authSelectionReason({ ABRA_AUTH: "passphrase" }, "linux")).toBe(
      "explicit ABRA_AUTH",
    );
  });

  it("resolveKeystoreBackend DI", () => {
    expect(resolveKeystoreBackend({}, "linux")).toBe("keytar");
    expect(resolveKeystoreBackend({ ABRA_KEYSTORE: "passphrase-file" }, "linux")).toBe(
      "passphrase-file",
    );
    expect(resolveKeystoreBackend({}, "darwin")).toBe("macos-keychain");
  });
});
