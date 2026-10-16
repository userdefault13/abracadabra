import os from "node:os";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AgentClientError } from "../agent/client.js";

const agentUnlockKey = vi.fn();
const unlockSession = vi.fn();

vi.mock("../platform/env.js", () => ({
  resolveKeystoreBackend: () => "passphrase-file",
  resolveAuthBackend: () => "passphrase",
}));
vi.mock("../core/prompt.js", () => ({
  promptHidden: async () => "correct horse",
  isNoTerminalError: () => false,
  NoTerminalError: class NoTerminalError extends Error {},
}));
vi.mock("../platform/keystore-passphrase.js", () => ({
  verifyVaultPassphrase: () => Buffer.alloc(32, 7),
}));
vi.mock("../platform/session.js", () => ({
  unlockSession: (k: Buffer) => unlockSession(k),
}));
vi.mock("../platform/index.js", () => ({
  lockSession: () => {},
  isSessionUnlocked: () => false,
  platformInfo: () => ({ keystore: "passphrase-file", vaultLocked: true }),
  authenticate: async () => {},
}));
vi.mock("../agent/index.js", async () => {
  const client = await vi.importActual<typeof import("../agent/client.js")>(
    "../agent/client.js",
  );
  return {
    AgentClientError: client.AgentClientError,
    shouldTryAgent: () => true,
    agentStatus: async () => ({ locked: true }),
    // An existing path so cmdUnlock's existsSync(socketPath) passes on every OS.
    resolveAgentSocketPath: () => os.tmpdir(),
    agentUnlockKey: (...a: unknown[]) => agentUnlockKey(...a),
  };
});

const { cmdUnlock, formatAgentUnlockFailure, EXIT_AGENT_REFUSED } = await import(
  "./unlock.js"
);

describe("cmdUnlock when abra-agent does not take the key (mocked client)", () => {
  let errs: string[];
  let logs: string[];

  beforeEach(() => {
    errs = [];
    logs = [];
    agentUnlockKey.mockReset();
    unlockSession.mockReset();
    vi.spyOn(console, "error").mockImplementation((m: unknown) => {
      errs.push(String(m));
    });
    vi.spyOn(console, "log").mockImplementation((m: unknown) => {
      logs.push(String(m));
    });
  });

  afterEach(() => {
    process.exitCode = undefined;
    vi.restoreAllMocks();
  });

  it("forbidden_peer ss_failed:timeout → exit 3, retry hint, both facts stated", async () => {
    agentUnlockKey.mockRejectedValue(
      new AgentClientError(
        "Peer is not the abra CLI",
        "forbidden_peer",
        "ss_failed:timeout",
        "ss timed out (system load?) — retry: abra unlock",
      ),
    );
    await cmdUnlock();
    expect(process.exitCode).toBe(EXIT_AGENT_REFUSED);
    expect(EXIT_AGENT_REFUSED).toBe(3);
    expect(unlockSession).toHaveBeenCalledTimes(1); // local unlock did happen
    expect(errs[0]).toContain("✗ abra-agent REFUSED unlock (reason: ss_failed:timeout)");
    expect(errs.join("\n")).toContain("retry: abra unlock");
    expect(errs.join("\n")).not.toContain("AF_NETLINK");
    expect(errs.join("\n")).toContain("Passphrase was correct");
    expect(logs).toEqual([]); // no ✓ success line
  });

  it("client timeout (agent busy/hung) is also loud and non-zero", async () => {
    agentUnlockKey.mockRejectedValue(
      new AgentClientError("Agent connect/read timed out", "timeout"),
    );
    await cmdUnlock();
    expect(process.exitCode).toBe(EXIT_AGENT_REFUSED);
    expect(errs[0]).toContain(
      "✗ abra-agent unlock FAILED (reason: timeout: Agent connect/read timed out)",
    );
    expect(errs.join("\n")).toContain("Rerun: abra unlock");
    expect([...logs, ...errs].some((l) => l.includes("✓"))).toBe(false);
  });

  it("success path still prints ✓ and leaves exit code alone", async () => {
    agentUnlockKey.mockResolvedValue(undefined);
    await cmdUnlock();
    expect(process.exitCode).toBeUndefined();
    expect(logs.some((l) => l.startsWith("✓") && l.includes("abra-agent holds the key"))).toBe(true);
    expect(errs).toEqual([]);
  });

  it("zeroes the key buffer even when the agent refuses", async () => {
    let pushed: Buffer | null = null;
    agentUnlockKey.mockImplementation(async (k: Buffer) => {
      pushed = k;
      throw new AgentClientError("nope", "forbidden_peer", "exe_mismatch");
    });
    await cmdUnlock();
    expect(pushed).not.toBeNull();
    expect(pushed!.every((b) => b === 0)).toBe(true);
  });
});

describe("formatAgentUnlockFailure", () => {
  it("colors only when asked", () => {
    const err = new AgentClientError("x", "forbidden_peer", "exe_mismatch", "Rerun: /n /c unlock");
    const plain = formatAgentUnlockFailure(err);
    const red = formatAgentUnlockFailure(err, { color: true });
    expect(plain[0]).not.toContain("\x1b[31m");
    expect(red[0].startsWith("\x1b[31m")).toBe(true);
    // Hint already carries a rerun line → no generic duplicate.
    expect(plain.filter((l) => l.includes("Rerun:")).length).toBe(1);
  });

  it("falls back to the error code when an older agent sends no reason", () => {
    const lines = formatAgentUnlockFailure(new AgentClientError("x", "forbidden_peer"));
    expect(lines[0]).toContain("REFUSED unlock (reason: forbidden_peer)");
    expect(lines.some((l) => l.includes("Rerun: abra unlock"))).toBe(true);
  });
});
